// Package bundlemerger provides functionality for merging and enriching payloads.
package bundlemerger

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"

	builderApi "github.com/attestantio/go-builder-client/api"
	apiv1deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	"github.com/attestantio/go-eth2-client/spec"
	relay_grpc "github.com/bloXroute-Labs/relay-grpc"
	"github.com/ethereum/go-ethereum/beacon/engine"
	bv "github.com/ethereum/go-ethereum/eth/block-validation"
	fbutils "github.com/flashbots/go-boost-utils/utils"
	"github.com/prof-project/go-bundle-merger/utils"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ServerOpts represents options for the bundle merger server.
type ServerOpts struct {
	BundleService *BundleServiceServer
	ExecClient    *rpc.Client
}

// Server represents the bundle merger server.
type Server struct {
	relay_grpc.UnimplementedEnricherServer
	pool                *TxBundlePool
	enrichedPayloadPool *EnrichedPayloadPool
	execClient          *rpc.Client
}

// NewBundleMergerServerEth creates a new bundle merger server for Ethereum.
func NewBundleMergerServerEth(opts ServerOpts) *Server {
	return &Server{
		pool:                opts.BundleService.txBundlePool,
		enrichedPayloadPool: NewEnrichedPayloadPool(10 * time.Minute), // Cleanup interval of 10 minutes
		execClient:          opts.ExecClient,
	}
}

func serializeBlock(block *types.Block) (string, error) {
	var buf bytes.Buffer
	err := rlp.Encode(&buf, block)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(buf.Bytes()), nil
}

// EnrichBlockStream implements the EnrichBlock RPC method as a bidirectional streaming RPC
func (s *Server) EnrichBlockStream(stream relay_grpc.Enricher_EnrichBlockStreamServer) error {
	log.Printf("[INFO] Starting new EnrichBlockStream connection")

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			log.Printf("[INFO] Client closed stream normally (EOF)")
			return nil
		}
		if status.Code(err) == codes.Canceled {
			log.Printf("[INFO] Client canceled the stream")
			return nil
		}
		if err != nil {
			log.Printf("[ERROR] Error receiving from stream: %v", err)
			return err
		}
		log.Printf("[INFO] Received new request with UUID: %s", req.Uuid)

		// Sanity check to ensure req has all required fields set
		if req.Uuid == "" {
			log.Printf("[ERROR] Missing required field: Uuid")
			return status.Errorf(codes.InvalidArgument, "missing required field: Uuid")
		}
		if req.ExecutionPayloadAndBlobsBundle == nil {
			log.Printf("[ERROR] Missing required field: ExecutionPayloadAndBlobsBundle")
			return status.Errorf(codes.InvalidArgument, "missing required field: ExecutionPayloadAndBlobsBundle")
		}
		if req.BidTrace == nil {
			log.Printf("[ERROR] Missing required field: BidTrace")
			return status.Errorf(codes.InvalidArgument, "missing required field: BidTrace")
		}
		if len(req.ParentBeaconRoot) == 0 {
			log.Printf("[ERROR] Missing required field: ParentBeaconRoot")
			return status.Errorf(codes.InvalidArgument, "missing required field: ParentBeaconRoot")
		}

		// Convert hex string value to uint64
		unEnrichedValueHex := strings.TrimPrefix(req.BidTrace.Value, "0x")
		unEnrichedValue, err := strconv.ParseUint(unEnrichedValueHex, 16, 64)
		if err != nil {
			log.Printf("[ERROR] Failed to parse unenriched value: %v", err)
			return status.Errorf(codes.Internal, "Failed to parse unenriched value: %v", err)
		}

		log.Printf("[INFO] Value of unenriched PBS block is: %s (decimal: %d)", req.BidTrace.Value, unEnrichedValue)

		log.Printf("[INFO] This is the fee recipient: %+v", req.ExecutionPayloadAndBlobsBundle.ExecutionPayload.FeeRecipient)
		log.Printf("[INFO] This is the proposer fee recipient: %+v", req.BidTrace.ProposerFeeRecipient)

		// Convert Proto Request to DenebRequest
		denebRequest, err := utils.ProtoRequestToDenebRequest(req)
		if err != nil {
			log.Printf("[ERROR] Error converting ProtoRequest to DenebRequest: %v", err)
			return status.Errorf(codes.InvalidArgument, "Invalid request: %v", err)
		}
		log.Printf("[INFO] Successfully converted request to DenebRequest")

		profBundle, err := s.getProfBundle()
		if err != nil {
			log.Printf("[ERROR] Failed to retrieve PROF bundle: %v", err)
			return status.Errorf(codes.Internal, "Error retrieving PROF bundle: %v", err)
		}
		log.Printf("[INFO] Successfully retrieved PROF bundle with %d transactions", len(profBundle))

		// Convert Deneb Request and Prof transactions to Block
		profBlock, err := engine.ExecutionPayloadV3ToBlockProf(denebRequest.PayloadBundle.ExecutionPayload, profBundle, denebRequest.PayloadBundle.BlobsBundle, denebRequest.ParentBeaconBlockRoot)
		if err != nil {
			log.Printf("[ERROR] Error converting Deneb Request and Prof transactions to Block: %v", err)
			return err
		}

		// log.Printf("[INFO] PROF block before execution %+v", profBlock)

		blockData, err := serializeBlock(profBlock)
		if err != nil {
			return err
		}

		// registeredGasLimit := profBlock.Header().GasLimit
		params := []interface{}{
			blockData,
			denebRequest.BidTrace.ProposerFeeRecipient,
			denebRequest.PayloadBundle.ExecutionPayload.GasLimit,
		}

		log.Printf("[INFO] Calling flashbots_validateProfBlock...")
		var profValidationResp *bv.ProfSimResp
		err = s.execClient.CallContext(context.Background(), &profValidationResp, "flashbots_validateProfBlock", params...)
		if err != nil {
			log.Printf("[ERROR] Error calling flashbots_validateProfBlock: %v", err)
			return status.Errorf(codes.Internal, "Error calling flashbots_validateProfBlock: %v", err)
		}
		log.Printf("[INFO] Successfully validated PROF block")

		// profValidationResp, err := s.profapi.ValidateProfBlock(block, common.Address(denebRequest.BidTrace.ProposerFeeRecipient), 0 /* TODO: suitable gaslimit?*/)
		// if err != nil {
		// 	return err
		// }

		// log.Printf("[INFO] profValidationResp %+v", profValidationResp)

		enrichedPayload := profValidationResp.ExecutionPayload
		if enrichedPayload == nil {
			return status.Errorf(codes.Internal, "Execution payload is nil")
		}
		// log.Printf("[INFO] Step 1: Got enriched payload: %+v", enrichedPayload)

		enrichedPayloadProto := utils.DenebPayloadToProtoPayload(enrichedPayload.ExecutionPayload)
		if enrichedPayloadProto == nil {
			return status.Errorf(codes.Internal, "Failed to convert to proto payload")
		}
		// log.Printf("[INFO] Step 2: Converted to proto payload: %+v", enrichedPayloadProto)

		enrichedBlobProto := utils.DenebBlobsBundleToProtoBlobsBundle(enrichedPayload.BlobsBundle)
		// log.Printf("[INFO] Step 3: Converted blobs bundle: %+v", enrichedBlobProto)

		// Instead of using req.Uuid as the key, use the block hash
		blockHash := enrichedPayload.ExecutionPayload.BlockHash.String()

		enrichedPayloadData := &EnrichedPayload{
			UUID: blockHash, // Store using block hash instead of request UUID
			Payload: &relay_grpc.ExecutionPayloadAndBlobsBundle{
				ExecutionPayload: enrichedPayloadProto,
				BlobsBundle:      enrichedBlobProto,
			},
			ReceivedAt: time.Now(),
		}
		// log.Printf("[INFO] Step 4: Created enriched payload data: %+v", enrichedPayloadData)

		s.enrichedPayloadPool.Add(enrichedPayloadData)
		// log.Printf("[INFO] Step 5: Added to pool")
		// log.Printf("[INFO] enrichedPayloadData blockHash %+v", enrichedPayloadData.UUID)

		enrichedPayloadHeader, err := fbutils.PayloadToPayloadHeader(
			&builderApi.VersionedExecutionPayload{
				Version: spec.DataVersionDeneb,
				Deneb:   enrichedPayload.ExecutionPayload,
			},
		)
		if err != nil {
			log.Printf("[ERROR] Error creating payload header: %v", err)
			return fmt.Errorf("failed to convert to payload header: %v", err)
		}
		// log.Printf("[INFO] Step 6: Created payload header: %+v", enrichedPayloadHeader)

		resp := &relay_grpc.EnrichBlockResponse{
			Uuid:                   req.Uuid,
			ExecutionPayloadHeader: utils.HeaderToProtoHeader(enrichedPayloadHeader.Deneb),
			KzgCommitment:          utils.CommitmentsToProtoCommitments(enrichedPayload.BlobsBundle.Commitments),
			Value:                  profValidationResp.Value.Uint64(),
		}
		log.Printf("[INFO] Step 7: Successfully created response")

		log.Printf("[INFO] Value of unenriched PBS block is: %+v", req.BidTrace.Value)

		log.Printf("[INFO] Value of enriched PBS block is: %+v", resp.Value)

		// Ensure enriched value is greater than unenriched value
		if resp.Value <= unEnrichedValue {
			log.Printf("[ERROR] Enriched block value (%d) is not greater than unenriched value (%d)",
				resp.Value, unEnrichedValue)
			return status.Errorf(codes.Internal,
				"Enriched block value must be greater than unenriched value")
		}

		log.Printf("[INFO] Sending response for UUID %s with block hash %s", req.Uuid, blockHash)
		if err := stream.Send(resp); err != nil {
			log.Printf("[ERROR] Failed to send response: %v", err)
			return fmt.Errorf("failed to send response: %v", err)
		}
		log.Printf("[INFO] Successfully sent response")
	}
}

func (s *Server) getProfBundle() ([][]byte, error) {
	// TODO: Change limit, currently set to 10 for testing purposes
	const bundleLimit = 20

	// Retrieve bundles from the pool
	bundles := s.pool.getBundlesForProcessing(bundleLimit, true)

	log.Printf("[INFO] bundles %+v", bundles)

	if len(bundles) == 0 {
		return nil, fmt.Errorf("no bundles available for processing")
	}

	var profBundles [][]byte
	totalValue := new(big.Int)

	for _, bundle := range bundles {
		for _, tx := range bundle.Txs {
			// Calculate the potential value of this transaction
			gasPrice := tx.GasPrice()
			gasLimit := tx.Gas()
			value := new(big.Int).Mul(gasPrice, new(big.Int).SetUint64(gasLimit))

			log.Printf("[DEBUG] Transaction value: %s wei (gasPrice: %s, gasLimit: %d)",
				value.String(),
				gasPrice.String(),
				gasLimit)

			totalValue.Add(totalValue, value)

			serializedTx, err := tx.MarshalBinary()
			if err != nil {
				return nil, fmt.Errorf("failed to serialize transaction: %v", err)
			}
			profBundles = append(profBundles, serializedTx)
		}
	}

	log.Printf("[DEBUG] Total potential value from transactions: %s wei", totalValue.String())

	return profBundles, nil
}

// GetEnrichedPayload retrieves an enriched payload.
func (s *Server) GetEnrichedPayload(_ context.Context, req *relay_grpc.GetEnrichedPayloadRequest) (*relay_grpc.ExecutionPayloadAndBlobsBundle, error) {
	// TODO: - Once payload is fetched, there is yet no marking for deletion --> To be added
	log.Printf("[INFO] CALLED ENRICH PAYLOAD")
	// Deserialize the blinded beacon block
	var blindedBlock apiv1deneb.BlindedBeaconBlock
	if err := json.Unmarshal(req.Message, &blindedBlock); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Failed to unmarshal beacon block: %v", err)
	}

	// Use the block hash from the execution payload header as the lookup key
	blockHash := blindedBlock.Body.ExecutionPayloadHeader.BlockHash.String()

	// Retrieve the enriched payload from the pool
	enrichedPayload, exists := s.enrichedPayloadPool.Get(blockHash)
	if !exists {
		return nil, status.Errorf(codes.NotFound, "Enriched payload not found for block hash: %s", blockHash)
	}
	log.Printf("[INFO] FOUND the requested enrichedPayload %+v", enrichedPayload)

	return enrichedPayload.Payload, nil
}
