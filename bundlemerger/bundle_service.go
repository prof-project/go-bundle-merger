// Package bundlemerger provides functionality for merging and enriching payloads.
package bundlemerger

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	pb "github.com/prof-project/prof-grpc/go/profpb"
)

// BundleServiceServer provides gRPC server methods for bundle services.
type BundleServiceServer struct {
	pb.UnimplementedBundleServiceServer
	txBundlePool *TxBundlePool
}

// NewBundleServiceServer creates a new BundleServiceServer.
func NewBundleServiceServer() *BundleServiceServer {
	txBundlePool := &TxBundlePool{
		bundles:    []*TxBundle{},
		bundleMap:  make(map[string]*TxBundle),
		customSort: sortByBlockNumber,
	}
	txBundlePool.startCleanupJob(5 * time.Second)

	return &BundleServiceServer{txBundlePool: txBundlePool}
}

// SendBundleCollections sends bundle collections to the server.
func (s *BundleServiceServer) SendBundleCollections(_ context.Context, req *pb.BundlesRequest) (*pb.BundlesResponse, error) {
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

		// Optional logging
		if false {
			log.Printf("Bundle BlockNumber: %s, MinTimestamp: %d, MaxTimestamp: %d", bundle.BlockNumber, bundle.MinTimestamp, bundle.MaxTimestamp)
			log.Printf("Bundle: %v", bundle)
		}

		// Convert the gRPC bundle to a TxBundle
		txBundle := &TxBundle{
			BlockNumber:       bundle.BlockNumber,
			MinTimestamp:      bundle.MinTimestamp,
			MaxTimestamp:      bundle.MaxTimestamp,
			RevertingTxHashes: bundle.RevertingTxHashes,
			ReplacementUUID:   bundle.ReplacementUuid,
			Builders:          bundle.Builders,
		}

		// Deserialize transactions from the gRPC bundle
		var err error
		txBundle.Txs, err = deserializeTransactions(bundle.Transactions)
		if err != nil {
			log.Printf("Failed to deserialize transactions: %v\n", err)
			return nil, err
		}

		// Optional logging
		if true {
			// Optional logging
			if false {
				// Log details of each transaction in the bundle
				for j, tx := range bundle.Transactions {
					log.Printf("(gRPC) Transaction %d: Data: %x", j+1, tx.Data)
				}
			}

			// Optional logging
			if false {
				// Log details of deserialized transactions in the bundle
				for j, tx := range txBundle.Txs {
					log.Printf("(deserialized) Transaction %d: To: %s, Nonce: %d, Gas: %d, Value: %s, Data: %v, Hash: %s, Size: %d", j+1, tx.To(), tx.Nonce(), tx.Gas(), tx.Value(), tx.Data(), tx.Hash(), tx.Size())

					// Derive the sender address based on the transaction type
					var signer types.Signer
					switch tx.Type() {
					case types.LegacyTxType:
						signer = types.HomesteadSigner{}
					case types.AccessListTxType:
						signer = types.NewEIP2930Signer(tx.ChainId())
					case types.DynamicFeeTxType:
						signer = types.NewLondonSigner(tx.ChainId())
					default:
						log.Printf("Unsupported transaction type: %d\n", tx.Type())
						continue
					}

					from, err := types.Sender(signer, tx)
					if err != nil {
						log.Printf("Failed to derive sender address: %v\n", err)
						continue
					}
					// Get the signature values
					v, r, s := tx.RawSignatureValues()

					log.Printf("Transaction details: %+v\n", tx)
					log.Printf("Sender address: %s\n", from.Hex())
					log.Printf("Signature values: v=%d, r=%x, s=%x\n", v, r, s)
				}
			}
		}

		// Add the bundle to the pool
		err = s.txBundlePool.addBundle(txBundle, true)
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
			statusMessage = fmt.Sprintf("Failed to processing bundle: %v", err)
			success = false
		} else {
			log.Printf("Bundle %d processed successfully", i+1)
			statusMessage = "Bundle processed successfully"
			success = true
		}

		// ToDo: mark for deletion after merging
		// err = s.txBundlePool.cancelBundleByUUID(bundle.ReplacementUuid)
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
	return response, nil
}

// deserializeTransactions takes a slice of BundleTransaction objects and returns a slice of Transaction objects
func deserializeTransactions(bundleTxs []*pb.BundleTransaction) ([]*types.Transaction, error) {
	var transactions []*types.Transaction
	for _, bundleTx := range bundleTxs {
		tx := new(types.Transaction)
		err := rlp.DecodeBytes(bundleTx.Data, tx)
		if err != nil {
			log.Printf("Failed to deserialize transaction: %v\n", err)
			return nil, err
		}
		transactions = append(transactions, tx)
	}
	return transactions, nil
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
