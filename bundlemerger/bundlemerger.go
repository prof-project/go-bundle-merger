package bundlemerger

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

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

var (
	ErrJSONDecodeFailed = errors.New("json error")
	ErrSimulationFailed = errors.New("simulation failed")
	ErrNoCapellaPayload = errors.New("capella payload is nil")
	ErrNoDenebPayload   = errors.New("deneb payload is nil")
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

// EnrichBlock implements the EnrichBlock RPC method as a bidirectional streaming RPC
func (s *BundleMergerServer) EnrichBlockStream(stream relay_grpc.Enricher_EnrichBlockStreamServer) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			fmt.Printf("Stream closed by client: %v\n", err)
			return nil
		}
		if err != nil {
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
		block, err := engine.ExecutionPayloadV3ToBlockProf(denebRequest.PayloadBundle.ExecutionPayload, profBundle, denebRequest.PayloadBundle.BlobsBundle, denebRequest.ParentBeaconBlockRoot)
		if err != nil {
			fmt.Printf("Error converting Deneb Request and Prof transactions to Block: %v\n", err)
			return err
		}

		fmt.Printf("PROF block before execution %+v\n", block)

		params := []interface{}{
			block,
			denebRequest.BidTrace.ProposerFeeRecipient,
			denebRequest.BidTrace.GasLimit,
		}

		// Create headers
		headers := http.Header{}
		headers.Add("X-Request-ID", fmt.Sprintf("%s", req.Uuid))
		headers.Add("X-High-Priority", "true")
		headers.Add("X-Fast-Track", "true")

		// Create JSON-RPC request
		var result bv.ProfSimResp
		err = s.execClient.Call(&result, "flashbots_validateProfBlock", params...)
		if err != nil {
			return status.Errorf(codes.Internal, "RPC call failed: %v", err)
		}

		fmt.Printf("profValidationResp %+v\n", result)

		enrichedPayload := result.ExecutionPayload
		enrichedPayloadProto := utils.DenebPayloadToProtoPayload(enrichedPayload.ExecutionPayload)
		enrichedBlobProto := utils.DenebBlobsBundleToProtoBlobsBundle(enrichedPayload.BlobsBundle)

		// Save the enriched payload in the pool
		enrichedPayloadData := &EnrichedPayload{
			UUID: req.Uuid,
			Payload: &relay_grpc.ExecutionPayloadAndBlobsBundle{
				ExecutionPayload: enrichedPayloadProto,
				BlobsBundle:      enrichedBlobProto,
			},
			ReceivedAt: time.Now(),
		}
		s.enrichedPayloadPool.Add(enrichedPayloadData)

		enrichedPayloadHeader, err := fbutils.PayloadToPayloadHeader(
			&builderApi.VersionedExecutionPayload{ //nolint:exhaustivestruct
				Version: spec.DataVersionDeneb,
				Deneb:   enrichedPayload.ExecutionPayload,
			},
		)
		if err != nil {
			return err
		}

		resp := &relay_grpc.EnrichBlockResponse{
			Uuid:                   req.Uuid,
			ExecutionPayloadHeader: utils.HeaderToProtoHeader(enrichedPayloadHeader.Deneb), // TODO: Check that this is implemented
			KzgCommitment:          utils.CommitmentsToProtoCommitments(enrichedPayload.BlobsBundle.Commitments),
			Value:                  result.Value.Uint64(), // TODO: https://github.com/prof-project/prof-grpc/issues/2
		}

		if err := stream.Send(resp); err != nil {
			return status.Errorf(codes.Internal, "Failed to send response: %v", err)
		}
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
