package bundlemerger

import (
	"context"
	"fmt"
	"io"
	"log"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	builderApi "github.com/attestantio/go-builder-client/api"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/ethereum/go-ethereum/beacon/engine"
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
	pool    *TxBundlePool // Add this line to include the pool
}

// NewBundleMergerServer creates a new BundleMergerServer
func NewBundleMergerServerEth(ethInstance *eth.Ethereum, bundleService *BundleServiceServer) *BundleMergerServer {
	// Initialize the BundleServiceServer to get the TxBundlePool
	return &BundleMergerServer{
		eth:     ethInstance,
		profapi: bv.NewBlockValidationAPI(ethInstance, nil, true, true),
		pool:    bundleService.txBundlePool, // Assign the pool from BundleServiceServer
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
			ExecutionPayloadHeader: utils.HeaderToProtoHeader(enrichedPayloadHeader.Deneb), // TODO: Check that this is implemented
			KzgCommitment:          utils.CommitmentsToProtoCommitments(enrichedPayload.BlobsBundle.Commitments),
			Value:                  profValidationResp.Value.Uint64(), // TODO: https://github.com/prof-project/prof-grpc/issues/2
		}

		if err := stream.Send(resp); err != nil {
			return status.Errorf(codes.Internal, "Failed to send response: %v", err)
		}
	}
}

func (s *BundleMergerServer) getProfBundle() ([][]byte, error) {
	// TODO: Change limit, currently set to 1 for testing purposes
	const bundleLimit = 1

	// Retrieve bundles from the pool
	bundles := s.pool.getBundlesForProcessing(bundleLimit)

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
	txBundlePool *TxBundlePool
}

// Initialize the BundleServiceServer with a TxBundlePool
func NewBundleServiceServer() *BundleServiceServer {
	txBundlePool := &TxBundlePool{
		bundles:    []*TxBundle{},
		bundleMap:  make(map[string]*TxBundle),
		customSort: sortByBlockNumber,
	}
	txBundlePool.startCleanupJob(5 * time.Second)

	return &BundleServiceServer{txBundlePool: txBundlePool}
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

		log.Printf("> Received %d bundles", len(req.Bundles))

		// Prepare to collect responses for each bundle
		var bundleResponses []*pb.BundleResponse

		// Process each bundle in the collection
		for i, bundle := range req.Bundles {
			log.Printf(">> Processing bundle %d with %d transactions", i+1, len(bundle.Transactions))

			// Log other bundle information
			log.Printf("Bundle BlockNumber: %s, MinTimestamp: %d, MaxTimestamp: %d",
				bundle.BlockNumber, bundle.MinTimestamp, bundle.MaxTimestamp)

			if bundle.ReplacementUuid != "" {
				log.Printf("ReplacementUuid: %s", bundle.ReplacementUuid)
			}

			// Optional fields
			if false {
				if len(bundle.RevertingTxHashes) > 0 {
					log.Printf("RevertingTxHashes: %v", bundle.RevertingTxHashes)
				}

				if len(bundle.Builders) > 0 {
					log.Printf("Builders: %v", bundle.Builders)
				}
			}

			// Convert the gRPC bundle to a TxBundle
			txBundle := &TxBundle{
				BlockNumber:       bundle.BlockNumber,
				MinTimestamp:      bundle.MinTimestamp,
				MaxTimestamp:      bundle.MaxTimestamp,
				RevertingTxHashes: bundle.RevertingTxHashes,
				ReplacementUuid:   bundle.ReplacementUuid,
				Builders:          bundle.Builders,
				Txs:               deserializeTransactions(bundle.Transactions),
			}

			// Log details of each transaction in the bundle
			for j, tx := range bundle.Transactions {
				log.Printf("(gRPC) Transaction %d: To: %s, Nonce: %d, Gas: %d, Value: %s, Data: %v",
					j+1, tx.To, tx.Nonce, tx.Gas, tx.Value, tx.Data)
			}

			// Log details of deserialized transactions in the bundle
			for j, tx := range txBundle.Txs {
				log.Printf("(deserialized) Transaction %d: To: %s, Nonce: %d, Gas: %d, Value: %s, Data: %v",
					j+1, tx.To(), tx.Nonce(), tx.Gas(), tx.Value(), tx.Data())
			}

			// Add the bundle to the pool
			err := s.txBundlePool.addBundle(txBundle, true)
			var statusMessage string
			var success bool

			if err != nil {
				log.Printf("Error adding bundle %d to pool: %v", i+1, err)
				statusMessage = fmt.Sprintf("Failed to add bundle to pool: %v", err)
				success = false
			} else {
				log.Printf("Bundle %d added to pool successfully", i+1)
				statusMessage = "Bundle added to pool successfully"
				success = true
			}

			// Simulate some processing (e.g., interacting with miners or MEV searchers)
			err = simulateBundleProcessing(bundle)
			if err != nil {
				log.Printf("Error processing bundle %d: %v", i+1, err)
				statusMessage = fmt.Sprintf("Failed to merge bundle: %v", err)
				success = false
			} else {
				log.Printf("Bundle %d processed successfully", i+1)
				statusMessage = "Bundle merged successfully"
				success = true
			}

			err = s.txBundlePool.cancelBundleByUuid(bundle.ReplacementUuid)
			if err != nil {
				// ToDo: Handle error
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

func deserializeTransactions(serialized []*pb.BundleTransaction) []*types.Transaction {
	var transactions []*types.Transaction
	for _, stx := range serialized {
		to := common.HexToAddress(stx.To)
		value, _ := new(big.Int).SetString(stx.Value, 10) // Convert string to big.Int

		tx := types.NewTransaction(
			stx.Nonce,
			to,
			value,
			stx.Gas,
			nil, // ToDo: GasPrice, not part of gRPC message for now
			stx.Data,
		)
		transactions = append(transactions, tx)
	}
	return transactions
}

// Simulate some bundle processing, like communication with miners or other external services
func simulateBundleProcessing(bundle *pb.Bundle) error {
	log.Printf("Simulating processing of bundle for BlockNumber %s", bundle.BlockNumber)
	time.Sleep(1 * time.Second)

	// Simulate a simple success case for now
	return nil
}
