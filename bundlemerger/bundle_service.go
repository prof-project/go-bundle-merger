package bundlemerger

import (
	"fmt"
	"io"
	"log"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	pb "github.com/prof-project/prof-grpc/go/profpb"
)

// Sequencer API
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
			// Optional logging
			if false {
				log.Printf(">> Processing bundle %d with %d transactions", i+1, len(bundle.Transactions))

				// Log other bundle information
				log.Printf("Bundle BlockNumber: %s, MinTimestamp: %d, MaxTimestamp: %d",
					bundle.BlockNumber, bundle.MinTimestamp, bundle.MaxTimestamp)

				if bundle.ReplacementUuid != "" {
					log.Printf("ReplacementUuid: %s", bundle.ReplacementUuid)
				}
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

			// Optional logging
			if false {
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
			}

			// Add the bundle to the pool
			err := s.txBundlePool.addBundle(txBundle, true)
			var statusMessage string
			var success bool

			// Optional logging
			if false {
				if err != nil {
					log.Printf("Error adding bundle %d to pool: %v", i+1, err)
					statusMessage = fmt.Sprintf("Failed to add bundle to pool: %v", err)
					success = false
				} else {
					log.Printf("Bundle %d added to pool successfully", i+1)
					statusMessage = "Bundle added to pool successfully"
					success = true
				}
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

			// ToDo: mark for deletion after merging
			// err = s.txBundlePool.cancelBundleByUuid(bundle.ReplacementUuid)
			// if err != nil {
			// 	// ToDo: Handle error
			// }

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
	// Optional logging
	if false {
		log.Printf("Simulating processing of bundle for BlockNumber %s", bundle.BlockNumber)
	}
	// Simulate a simple success case for now
	return nil
}
