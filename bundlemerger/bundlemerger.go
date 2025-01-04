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

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/holiman/uint256"

	builderApi "github.com/attestantio/go-builder-client/api"
	apiv1deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	"github.com/attestantio/go-eth2-client/spec"
	relay_grpc "github.com/bloXroute-Labs/relay-grpc"
	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethpandaops/spamoor/txbuilder"
	fbutils "github.com/flashbots/go-boost-utils/utils"
	"github.com/prof-project/go-bundle-merger/utils"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type BundleMergerServerOpts struct {
	BundleService *BundleServiceServer
	ExecClient    *rpc.Client
	WalletPrivKey string
}

// BundleMergerServer implements the BundleMerger gRPC service
type BundleMergerServer struct {
	relay_grpc.UnimplementedEnricherServer
	pool                *TxBundlePool
	enrichedPayloadPool *EnrichedPayloadPool
	execClient          *rpc.Client
	wallet              *txbuilder.Wallet
}

type profValidationResponse struct {
	Value          *big.Int
	FinalizedBlock *types.Block
}

func NewBundleMergerServerEth(opts BundleMergerServerOpts) *BundleMergerServer {
	// Initialize wallet with chainID
	wallet, err := txbuilder.NewWallet(opts.WalletPrivKey)
	if err != nil {
		log.Printf("[ERROR] Failed to initialize wallet: %v", err)
		return nil
	}

	return &BundleMergerServer{
		pool:                opts.BundleService.txBundlePool,
		enrichedPayloadPool: NewEnrichedPayloadPool(10 * time.Minute),
		execClient:          opts.ExecClient,
		wallet:              wallet,
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

		// Add the direct payment transaction if needed
		if denebRequest.BidTrace.ProposerFeeRecipient != denebRequest.PayloadBundle.ExecutionPayload.FeeRecipient {
			log.Printf("[INFO] Fee recipient is not the same as the proposer fee recipient, adding tx to prof bundle")

			// Set fee caps (in Gwei)
			// new(big.Int).Mul(big.NewInt(int64(s.options.BaseFee)), big.NewInt(1000000000))
			feeCap := new(big.Int).Mul(big.NewInt(int64(150)), big.NewInt(1000000000)) // 150 Gwei
			tipCap := new(big.Int).Mul(big.NewInt(int64(140)), big.NewInt(1000000000)) // 140 Gwei

			log.Printf("[INFO] wallet chainID %+v", s.wallet.GetChainId())

			// Set chainID to 17000
			s.wallet.SetChainId(big.NewInt(17000))

			log.Printf("[INFO] wallet updated chainID %+v", s.wallet.GetChainId())

			// Set amount (in Gwei)
			amount := uint256.NewInt(1000000) // 1000 Gwei
			amount = amount.Mul(amount, uint256.NewInt(1000000000))

			// Convert proposer fee recipient to common.Address
			proposerAddr := common.BytesToAddress(req.BidTrace.ProposerFeeRecipient[:])

			log.Printf("[INFO] proposerAddr %+v", proposerAddr)

			// Create direct payment transaction data
			txData, err := txbuilder.DynFeeTx(&txbuilder.TxMetadata{
				GasFeeCap: uint256.MustFromBig(feeCap),
				GasTipCap: uint256.MustFromBig(tipCap),
				Gas:       21000, // Standard ETH transfer gas limit
				To:        &proposerAddr,
				Value:     amount,
				Data:      []byte{},
			})
			if err != nil {
				log.Printf("[ERROR] Failed to create direct payment tx: %v", err)
				return status.Errorf(codes.Internal, "Failed to create direct payment tx: %v", err)
			}

			// Build and sign the transation
			signedTx, err := s.wallet.ReplaceDynamicFeeTx(txData, 0)
			if err != nil {
				log.Printf("[ERROR] Failed to build and sign transaction: %v", err)
				return status.Errorf(codes.Internal, "Failed to build and sign transaction: %v", err)
			}

			// Serialize the signed transaction
			serializedTx, err := signedTx.MarshalBinary()
			if err != nil {
				log.Printf("[ERROR] Failed to serialize transaction: %v", err)
				return status.Errorf(codes.Internal, "Failed to serialize transaction: %v", err)
			}

			// Add the serialized transaction to prof bundle
			profBundle = append(profBundle, serializedTx)
			log.Printf("[INFO] profBundle %+v", profBundle)
		}

		// Convert Deneb Request and Prof transactions to Block
		profBlock, err := utils.ExecutionPayloadV3ToBlock(denebRequest.PayloadBundle.ExecutionPayload, profBundle, denebRequest.PayloadBundle.BlobsBundle, denebRequest.ParentBeaconBlockRoot)
		if err != nil {
			log.Printf("[ERROR] Error converting Deneb Request and Prof transactions to Block: %v", err)
			return err
		}

		log.Printf("[INFO] PROF block before execution %+v", profBlock)

		blockData, err := serializeBlock(profBlock)
		if err != nil {
			return err
		}

		params := []interface{}{
			blockData,
			denebRequest.BidTrace.ProposerFeeRecipient,
			denebRequest.PayloadBundle.ExecutionPayload.GasLimit,
		}

		log.Printf("[INFO] Calling flashbots_validateProfBlock...")
		var profValidationResp *profValidationResponse
		err = s.execClient.CallContext(context.Background(), &profValidationResp, "flashbots_validateProfBlock", params...)
		if err != nil {
			log.Printf("[ERROR] Error calling flashbots_validateProfBlock: %v", err)
			return status.Errorf(codes.Internal, "Error calling flashbots_validateProfBlock: %v", err)
		}
		log.Printf("[INFO] Successfully validated PROF block")

		log.Printf("[INFO] profValidationResp %+v", profValidationResp)

		// Log block details for debugging
		log.Printf("[INFO] Block validation details:")
		if profValidationResp == nil {
			log.Printf("[ERROR] profValidationResp is nil")
			return status.Errorf(codes.Internal, "profValidationResp is nil")
		}

		block := profValidationResp.FinalizedBlock
		if block == nil {
			log.Printf("[ERROR] FinalizedBlock is nil")
			return status.Errorf(codes.Internal, "FinalizedBlock is nil")
		}
		log.Printf("[INFO] FinalizedBlock %+v", block)

		// Check each method call separately
		if number := block.Number(); number != nil {
			log.Printf("  Number: %d", number.Uint64())
		} else {
			log.Printf("  Number: nil")
		}

		if hash := block.Hash(); (hash != common.Hash{}) {
			log.Printf("  Hash: %s", hash.Hex())
		} else {
			log.Printf("  Hash: nil")
		}

		if parentHash := block.ParentHash(); (parentHash != common.Hash{}) {
			log.Printf("  ParentHash: %s", parentHash.Hex())
		} else {
			log.Printf("  ParentHash: nil")
		}

		if coinbase := block.Coinbase(); (coinbase != common.Address{}) {
			log.Printf("  Coinbase: %s", coinbase.Hex())
		} else {
			log.Printf("  Coinbase: nil")
		}

		if baseFee := block.BaseFee(); baseFee != nil {
			log.Printf("  BaseFee: %s", baseFee.String())
		} else {
			log.Printf("  BaseFee: nil")
		}

		if txs := block.Transactions(); txs != nil {
			log.Printf("  Transactions: %d", len(txs))
		} else {
			log.Printf("  Transactions: nil")
		}

		log.Printf("  Withdrawals: %v", block.Withdrawals() != nil)
		log.Printf("  BlobGasUsed: %v", block.BlobGasUsed())
		log.Printf("  ExcessBlobGas: %v", block.ExcessBlobGas())

		// Convert the blobs bundle to blob sidecars
		blobSidecars := make([]*types.BlobTxSidecar, len(denebRequest.PayloadBundle.BlobsBundle.Blobs))
		for i := range denebRequest.PayloadBundle.BlobsBundle.Blobs {
			var blob kzg4844.Blob
			var commitment kzg4844.Commitment
			var proof kzg4844.Proof

			copy(blob[:], denebRequest.PayloadBundle.BlobsBundle.Blobs[i][:])
			copy(commitment[:], denebRequest.PayloadBundle.BlobsBundle.Commitments[i][:])
			copy(proof[:], denebRequest.PayloadBundle.BlobsBundle.Proofs[i][:])

			blobSidecars[i] = &types.BlobTxSidecar{
				Blobs:       []kzg4844.Blob{blob},
				Commitments: []kzg4844.Commitment{commitment},
				Proofs:      []kzg4844.Proof{proof},
			}
		}

		log.Printf("[INFO] successfully created blobSidecars %+v", blobSidecars)

		enrichedPayload := engine.BlockToExecutableData(profValidationResp.FinalizedBlock, profValidationResp.Value, blobSidecars, nil)

		log.Printf("[INFO] successfully created enrichedPayload %+v", enrichedPayload)

		payload, err := utils.GetDenebPayload(enrichedPayload)
		if err != nil {
			log.Printf("[ERROR] Error getting Deneb payload: %v", err)
			return status.Errorf(codes.Internal, "Error getting Deneb payload: %v", err)
		}

		if enrichedPayload == nil {
			return status.Errorf(codes.Internal, "Execution payload is nil")
		}
		// log.Printf("[INFO] Step 1: Got enriched payload: %+v", enrichedPayload)

		enrichedPayloadProto := utils.DenebPayloadToProtoPayload(payload.ExecutionPayload)
		if enrichedPayloadProto == nil {
			return status.Errorf(codes.Internal, "Failed to convert to proto payload")
		}
		// log.Printf("[INFO] Step 2: Converted to proto payload: %+v", enrichedPayloadProto)

		enrichedBlobProto := utils.DenebBlobsBundleToProtoBlobsBundle(payload.BlobsBundle)
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
				Deneb:   payload.ExecutionPayload,
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
			KzgCommitment:          utils.CommitmentsToProtoCommitments(payload.BlobsBundle.Commitments),
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

func (s *BundleMergerServer) getProfBundle() ([][]byte, error) {
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

// TODO - Once payload is fetched, there is yet no marking for deletion --> To be added
func (s *BundleMergerServer) GetEnrichedPayload(ctx context.Context, req *relay_grpc.GetEnrichedPayloadRequest) (*relay_grpc.ExecutionPayloadAndBlobsBundle, error) {

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
