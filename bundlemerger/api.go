package bundlemerger

import (
	"context"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/prof-project/go-bundle-merger/utils"
	pb "github.com/prof-project/prof-grpc/go/profpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// BundleMergerServer implements the BundleMerger gRPC service
type BundleMergerServer struct {
	pb.UnimplementedBundleMergerServer
	eth *eth.Ethereum
}

// NewBundleMergerServer creates a new BundleMergerServer
func NewBundleMergerServerEth(ethInstance *eth.Ethereum) *BundleMergerServer {
	return &BundleMergerServer{
		eth: ethInstance,
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
		block, err := engine.ExecutionPayloadV3ToBlock(denebRequest.PayloadBundle.ExecutionPayload, denebRequest.PayloadBundle.BlobsBundle, denebRequest.ParentBeaconBlockRoot)
		if err != nil {
			return err
		}

		// Print Block to see that reqconstruction from gRPC works
		fmt.Printf("got ExecutionPayloadV3ToBlock %+v\n", block)

		// TODO - Currently returns empty DUMMY response, need to get tx from prof bundle
		resp := &pb.EnrichBlockResponse{
			Uuid:                   req.Uuid,
			ExecutionPayloadHeader: &pb.ExecutionPayloadHeader{},
			KzgCommitment:          [][]byte{}, // Updated to match the correct type
			Value:                  0,
		}

		if err := stream.Send(resp); err != nil {
			return status.Errorf(codes.Internal, "Failed to send response: %v", err)
		}
	}
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

////Sequencer API

type BundleServiceServer struct {
	pb.UnimplementedBundleServiceServer
}

// Implement the StreamBundleCollections rpc of the BundleService service
func (s *BundleServiceServer) StreamBundleCollections(stream pb.BundleService_StreamBundleCollectionsServer) error {
	for {
		// Receive the next collection of bundles from the client
		req, err := stream.Recv()
		if err == io.EOF {
			// No more collections from the client
			return nil
		}
		if err != nil {
			return err
		}

		log.Printf("Received %d bundles", len(req.Bundles))

		// Prepare to collect responses for each bundle
		var bundleResponses []*pb.BundleResponse

		// Process each bundle in the collection
		for i, bundle := range req.Bundles {
			log.Printf("Processing bundle %d with %d transactions", i+1, len(bundle.Transactions))

			// Log details of each transaction in the bundle
			for j, tx := range bundle.Transactions {
				log.Printf("Transaction %d: To: %s, Nonce: %d, Gas: %d, Value: %s",
					j+1, tx.To, tx.Nonce, tx.Gas, tx.Value)
			}

			// Log other bundle information
			log.Printf("Bundle BlockNumber: %s, MinTimestamp: %d, MaxTimestamp: %d",
				bundle.BlockNumber, bundle.MinTimestamp, bundle.MaxTimestamp)

			// Optional fields
			if len(bundle.RevertingTxHashes) > 0 {
				log.Printf("RevertingTxHashes: %v", bundle.RevertingTxHashes)
			}
			if bundle.ReplacementUuid != "" {
				log.Printf("ReplacementUuid: %s", bundle.ReplacementUuid)
			}
			if len(bundle.Builders) > 0 {
				log.Printf("Builders: %v", bundle.Builders)
			}

			// Simulate some processing (e.g., interacting with miners or MEV searchers)
			err := simulateBundleProcessing(bundle)
			var statusMessage string
			var success bool

			if err != nil {
				log.Printf("Error processing bundle %d: %v", i+1, err)
				statusMessage = fmt.Sprintf("Failed to merge bundle: %v", err)
				success = false
			} else {
				log.Printf("Bundle %d processed successfully", i+1)
				statusMessage = "Bundle merged successfully"
				success = true
			}

			// Add response for the current bundle, including its UUID and processing result
			bundleResponses = append(bundleResponses, &pb.BundleResponse{
				ReplacementUuid: bundle.ReplacementUuid,
				Status:          statusMessage,
				Success:         success,
			})
		}

		// Send the response for the entire collection of bundles
		response := &pb.BundlesResponse{
			BundleResponses: bundleResponses,
		}
		if err := stream.Send(response); err != nil {
			return err
		}
	}
}

// Simulate some bundle processing, like communication with miners or other external services
func simulateBundleProcessing(bundle *pb.Bundle) error {
	log.Printf("Simulating processing of bundle for BlockNumber %s", bundle.BlockNumber)
	time.Sleep(1 * time.Second)

	// Simulate a simple success case for now
	return nil
}
