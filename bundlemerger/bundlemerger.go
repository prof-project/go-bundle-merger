package bundlemerger

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"

	builderApi "github.com/attestantio/go-builder-client/api"
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

		// Convert Deneb Request to Block
		pbsBlock, err := engine.ExecutionPayloadV3ToBlock(denebRequest.PayloadBundle.ExecutionPayload, denebRequest.PayloadBundle.BlobsBundle, denebRequest.ParentBeaconBlockRoot)
		if err != nil {
			return err
		}

		// Print Block to see that reconstruction from gRPC works
		fmt.Printf("got ExecutionPayloadV3ToBlock %+v\n", pbsBlock)

		profBundle, err := s.getProfBundle()

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
		params := []interface{}{
			blockData,
			denebRequest.BidTrace.ProposerFeeRecipient,
			uint64(0), // Set a suitable gas limit
		}

		var profValidationResp *bv.ProfSimResp
		err = s.execClient.CallContext(context.Background(), &profValidationResp, "flashbots_validateProfBlock", params...)
		if err != nil {
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

		// Save the enriched payload in the pool
		enrichedPayloadData := &EnrichedPayload{
			UUID: req.Uuid,
			Payload: &relay_grpc.ExecutionPayloadAndBlobsBundle{
				ExecutionPayload: enrichedPayloadProto,
				BlobsBundle:      enrichedBlobProto,
			},
			ReceivedAt: time.Now(),
		}
		fmt.Printf("Step 4: Created enriched payload data: %+v\n", enrichedPayloadData)

		s.enrichedPayloadPool.Add(enrichedPayloadData)
		fmt.Printf("Step 5: Added to pool\n")

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
	// Extract the UUID from the request message
	uuid := string(req.Message)

	// Retrieve the enriched payload from the pool
	enrichedPayload, exists := s.enrichedPayloadPool.Get(uuid)
	if !exists {
		return nil, status.Errorf(codes.NotFound, "Enriched payload not found for UUID: %s", uuid)
	}

	// Create and return the response
	response := &relay_grpc.ExecutionPayloadAndBlobsBundle{
		ExecutionPayload: enrichedPayload.Payload.ExecutionPayload,
		BlobsBundle:      enrichedPayload.Payload.BlobsBundle,
	}
	return response, nil
}
