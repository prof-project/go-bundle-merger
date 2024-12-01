package bundlemerger

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"

	builderApi "github.com/attestantio/go-builder-client/api"
	apiv1deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/ethereum/go-ethereum/beacon/engine"
	bv "github.com/ethereum/go-ethereum/eth/block-validation"
	fbutils "github.com/flashbots/go-boost-utils/utils"
	"github.com/prof-project/go-bundle-merger/utils"
	relay_grpc "github.com/prof-project/prof-grpc/go/relay_grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type BundleMergerServerOpts struct {
	BundleService *BundleServiceServer
	ExecClient    *rpc.Client
}

// BundleMergerServer implements the BundleMerger gRPC service
type BundleMergerServer struct {
	relay_grpc.UnimplementedEnricherServer
	pool                *TxBundlePool
	enrichedPayloadPool *EnrichedPayloadPool
	execClient          *rpc.Client
}

func NewBundleMergerServerEth(opts BundleMergerServerOpts) *BundleMergerServer {
	return &BundleMergerServer{
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

// EnrichBlock implements the EnrichBlock RPC method as a bidirectional streaming RPC
func (s *BundleMergerServer) EnrichBlockStream(stream relay_grpc.Enricher_EnrichBlockStreamServer) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			// Client closed stream normally
			return nil
		}
		if status.Code(err) == codes.Canceled {
			// Client canceled the stream - this is normal
			return nil
		}
		if err != nil {
			// Log other errors and return them
			fmt.Printf("Error receiving from stream: %v\n", err)
			return err
		}

		// Convert Proto Request to DenebRequest
		denebRequest, err := utils.ProtoRequestToDenebRequest(req)
		if err != nil {
			fmt.Printf("Error converting ProtoRequest to DenebRequest: %v\n", err)
			return status.Errorf(codes.InvalidArgument, "Invalid request: %v", err)
		}

		profBundle, err := s.getProfBundle()

		// fmt.Printf("profBundle %+v\n", profBundle)

		if err != nil {
			return status.Errorf(codes.Internal, "Error retrieving PROF bundle: %v", err)
		}

		// Convert Deneb Request and Prof transactions to Block
		profBlock, err := engine.ExecutionPayloadV3ToBlockProf(denebRequest.PayloadBundle.ExecutionPayload, profBundle, denebRequest.PayloadBundle.BlobsBundle, denebRequest.ParentBeaconBlockRoot)
		if err != nil {
			fmt.Printf("Error converting Deneb Request and Prof transactions to Block: %v\n", err)
			return err
		}
		fmt.Printf("PROF block before execution %+v\n", profBlock)

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

		var profValidationResp *bv.ProfSimResp
		err = s.execClient.CallContext(context.Background(), &profValidationResp, "flashbots_validateProfBlock", params...)
		if err != nil {
			fmt.Printf("Error calling flashbots_validateProfBlock: %v\n", err)
			return status.Errorf(codes.Internal, "Error calling flashbots_validateProfBlock: %v", err)
		}

		// profValidationResp, err := s.profapi.ValidateProfBlock(block, common.Address(denebRequest.BidTrace.ProposerFeeRecipient), 0 /* TODO: suitable gaslimit?*/)
		// if err != nil {
		// 	return err
		// }

		fmt.Printf("profValidationResp %+v\n", profValidationResp)

		enrichedPayload := profValidationResp.ExecutionPayload
		if enrichedPayload == nil {
			return status.Errorf(codes.Internal, "Execution payload is nil")
		}
		fmt.Printf("Step 1: Got enriched payload: %+v\n", enrichedPayload)

		enrichedPayloadProto := utils.DenebPayloadToProtoPayload(enrichedPayload.ExecutionPayload)
		if enrichedPayloadProto == nil {
			return status.Errorf(codes.Internal, "Failed to convert to proto payload")
		}
		fmt.Printf("Step 2: Converted to proto payload: %+v\n", enrichedPayloadProto)

		enrichedBlobProto := utils.DenebBlobsBundleToProtoBlobsBundle(enrichedPayload.BlobsBundle)
		fmt.Printf("Step 3: Converted blobs bundle: %+v\n", enrichedBlobProto)

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
		fmt.Printf("Step 4: Created enriched payload data: %+v\n", enrichedPayloadData)

		s.enrichedPayloadPool.Add(enrichedPayloadData)
		fmt.Printf("Step 5: Added to pool\n")
		fmt.Printf("enrichedPayloadData blockHash %+v\n", enrichedPayloadData.UUID)

		enrichedPayloadHeader, err := fbutils.PayloadToPayloadHeader(
			&builderApi.VersionedExecutionPayload{
				Version: spec.DataVersionDeneb,
				Deneb:   enrichedPayload.ExecutionPayload,
			},
		)
		if err != nil {
			fmt.Printf("Error creating payload header: %v\n", err)
			return fmt.Errorf("failed to convert to payload header: %v", err)
		}
		fmt.Printf("Step 6: Created payload header: %+v\n", enrichedPayloadHeader)

		resp := &relay_grpc.EnrichBlockResponse{
			Uuid:                   req.Uuid,
			ExecutionPayloadHeader: utils.HeaderToProtoHeader(enrichedPayloadHeader.Deneb),
			KzgCommitment:          utils.CommitmentsToProtoCommitments(enrichedPayload.BlobsBundle.Commitments),
			Value:                  profValidationResp.Value.Uint64(),
		}
		fmt.Printf("Step 7: Created response: %+v\n", resp)

		if err := stream.Send(resp); err != nil {
			return fmt.Errorf("failed to send response: %v", err)
		}
		fmt.Printf("Step 8: Sent response\n")
	}
}

func (s *BundleMergerServer) getProfBundle() ([][]byte, error) {
	// TODO: Change limit, currently set to 10 for testing purposes
	const bundleLimit = 10

	// Retrieve bundles from the pool
	bundles := s.pool.getBundlesForProcessing(bundleLimit, true)

	fmt.Printf("bundles %+v\n", bundles)

	if len(bundles) == 0 {
		return nil, fmt.Errorf("no bundles available for processing")
	}

	var profBundles [][]byte

	for _, bundle := range bundles {
		for _, tx := range bundle.Txs {
			// Serialize each transaction to RLP (or any other required format)
			serializedTx, err := tx.MarshalBinary()
			if err != nil {
				return nil, fmt.Errorf("failed to serialize transaction: %v", err)
			}
			profBundles = append(profBundles, serializedTx)
		}
	}

	return profBundles, nil
}

// TODO - Once payload is fetched, there is yet no marking for deletion --> To be added
func (s *BundleMergerServer) GetEnrichedPayload(ctx context.Context, req *relay_grpc.GetEnrichedPayloadRequest) (*relay_grpc.ExecutionPayloadAndBlobsBundle, error) {
	
	fmt.Printf("CALLED ENRICH PAYLOAD")
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
	fmt.Printf("FOUND the requested enrichedPayload %+v\n", enrichedPayload)

	return enrichedPayload.Payload, nil
}
