package bundlemerger

import (
	"context"
	"fmt"
	"io"

	builderApi "github.com/attestantio/go-builder-client/api"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/eth"
	bv "github.com/ethereum/go-ethereum/eth/block-validation"
	fbutils "github.com/flashbots/go-boost-utils/utils"
	"github.com/prof-project/go-bundle-merger/utils"
	pb "github.com/prof-project/prof-grpc/go/profpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// BundleMergerServer implements the BundleMerger gRPC service
type BundleMergerServer struct {
	pb.UnimplementedBundleMergerServer
	eth     *eth.Ethereum
	profapi *bv.BlockValidationAPI
}

// NewBundleMergerServer creates a new BundleMergerServer
func NewBundleMergerServerEth(ethInstance *eth.Ethereum) *BundleMergerServer {
	return &BundleMergerServer{
		eth:     ethInstance,
		profapi: bv.NewBlockValidationAPI(ethInstance, nil, true, true), // TODO: profAPI.validateProfBlock does not respect the last two args, always treats them as true
	}
}

// NewBundleMergerServer creates a new BundleMergerServer
func NewBundleMergerServer() *BundleMergerServer {
	return &BundleMergerServer{}
}

// EnrichBlock implements the EnrichBlock RPC method as a bidirectional streaming RPC
func (s *BundleMergerServer) EnrichBlock(stream pb.BundleMerger_EnrichBlockServer) error {

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return status.Errorf(codes.Internal, "Request closed by client: %v", err)
		}
		if err != nil {
			return status.Errorf(codes.Internal, "Failed to receive request: %v", err)
		}

		// Convert Proto Request from gRPC to DenebRequest
		denebRequest, err := utils.ProtoRequestToDenebRequest(req)
		if err != nil {
			return err
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
			return err
		}

		fmt.Printf("PROF block before execution %+v\n", block)

		profValidationResp, err := s.profapi.ValidateProfBlock(block, common.Address(denebRequest.BidTrace.ProposerFeeRecipient), 0 /* TODO: suitable gaslimit?*/)
		if err != nil {
			return err
		}

		enrichedPayload := profValidationResp.ExecutionPayload
		// TODO: save the execution payload.

		enrichedPayloadHeader, err := fbutils.PayloadToPayloadHeader(
			&builderApi.VersionedExecutionPayload{ //nolint:exhaustivestruct
				Version: spec.DataVersionDeneb,
				Deneb:   enrichedPayload.ExecutionPayload,
			},
		)
		if err != nil {
			return err
		}

		resp := &pb.EnrichBlockResponse{
			Uuid:                   req.Uuid,
			ExecutionPayloadHeader: utils.HeaderToProtoHeader(enrichedPayloadHeader.Deneb),
			KzgCommitment:          utils.CommitmentsToProtoCommitments(enrichedPayload.BlobsBundle.Commitments),
			Value:                  profValidationResp.Value.Uint64(), // TODO: https://github.com/prof-project/prof-grpc/issues/2
		}

		if err := stream.Send(resp); err != nil {
			return status.Errorf(codes.Internal, "Failed to send response: %v", err)
		}
	}
}

func (s *BundleMergerServer) getProfBundle() ([][]byte, error) {
	// TODO : will need to come from the sequencer
	return make([][]byte, 0), nil
}

// GetEnrichedPayload implements the GetEnrichedPayload RPC method
func (s *BundleMergerServer) GetEnrichedPayload(ctx context.Context, req *pb.GetEnrichedPayloadRequest) (*pb.ExecutionPayloadAndBlobsBundle, error) {
	// TODO: Implement the logic to get the enriched payload
	// This logic is currently situated in eth/block-validation
	// For now, we'll return a placeholder response

	// Simulating a case where the payload is not found
	return &pb.ExecutionPayloadAndBlobsBundle{
		ExecutionPayload: &pb.ExecutionPayloadUncompressed{},
		BlobsBundle:      &pb.BlobsBundle{},
	}, nil

	// Uncomment and modify the following to return an actual payload
	/*
		return &pb.GetEnrichedPayloadResponse{
			Uuid: req.Uuid,
			PayloadOrEmpty: &pb.GetEnrichedPayloadResponse_PayloadBundle{
				PayloadBundle: &pb.ExecutionPayloadAndBlobsBundle{
					ExecutionPayload: &pb.ExecutionPayload{},
					BlobsBundle:      &pb.BlobsBundle{},
				},
			},
		}, nil
	*/
}
