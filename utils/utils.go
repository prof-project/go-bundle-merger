// Package utils provides utility functions for the bundle merger.
package utils

import (
	"fmt"
	"math/big"

	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	v1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	consensus "github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	relay_grpc "github.com/bloXroute-Labs/relay-grpc"
	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/holiman/uint256"
)

// ExecutionPayloadToProtoEnrichBlockRequest converts an execution payload to a proto enrich block request.
func ExecutionPayloadToProtoEnrichBlockRequest(uuid string,
	executionPayload *builderApiDeneb.ExecutionPayloadAndBlobsBundle,
	bidTrace v1.BidTrace, parentBeaconRoot phase0.Root) relay_grpc.EnrichBlockRequest {
	BidTrace := &relay_grpc.BidTrace{
		Slot:                 bidTrace.Slot,
		ParentHash:           bidTrace.ParentHash[:],
		BlockHash:            bidTrace.BlockHash[:],
		BuilderPubkey:        bidTrace.BuilderPubkey[:],
		ProposerPubkey:       bidTrace.ProposerPubkey[:],
		ProposerFeeRecipient: bidTrace.ProposerFeeRecipient[:],
		GasLimit:             bidTrace.GasLimit,
		GasUsed:              bidTrace.GasUsed,
		Value:                bidTrace.Value.Hex(),
		BlobGasUsed:          executionPayload.ExecutionPayload.BlobGasUsed,
		ExcessBlobGas:        executionPayload.ExecutionPayload.ExcessBlobGas,
	}
	execPayloadAndBlobsBundle := ExecutionPayloadToProtoExecutionPayloadAndBlobsBundle(executionPayload)
	return relay_grpc.EnrichBlockRequest{
		Uuid:                           uuid,
		ExecutionPayloadAndBlobsBundle: execPayloadAndBlobsBundle,
		BidTrace:                       BidTrace,
		ParentBeaconRoot:               parentBeaconRoot[:],
	}
}

// ExecutionPayloadToProtoExecutionPayloadAndBlobsBundle converts an execution payload to a proto execution payload and blobs bundle.
func ExecutionPayloadToProtoExecutionPayloadAndBlobsBundle(executionPayload *builderApiDeneb.ExecutionPayloadAndBlobsBundle) *relay_grpc.ExecutionPayloadAndBlobsBundle {
	transactions := make([]*relay_grpc.Transaction, len(executionPayload.ExecutionPayload.Transactions))
	for i, tx := range executionPayload.ExecutionPayload.Transactions {
		transactions[i] = &relay_grpc.Transaction{
			RawData: tx,
		}
	}
	withdrawals := make([]*relay_grpc.Withdrawal, len(executionPayload.ExecutionPayload.Withdrawals))
	for i, withdrawal := range executionPayload.ExecutionPayload.Withdrawals {
		withdrawals[i] = &relay_grpc.Withdrawal{
			ValidatorIndex: uint64(withdrawal.ValidatorIndex),
			Index:          uint64(withdrawal.Index),
			Amount:         uint64(withdrawal.Amount),
			Address:        withdrawal.Address[:],
		}
	}
	ExecutionPayloadUncompressed := &relay_grpc.ExecutionPayloadUncompressed{
		ParentHash:    executionPayload.ExecutionPayload.ParentHash[:],
		StateRoot:     executionPayload.ExecutionPayload.StateRoot[:],
		ReceiptsRoot:  executionPayload.ExecutionPayload.ReceiptsRoot[:],
		LogsBloom:     executionPayload.ExecutionPayload.LogsBloom[:],
		PrevRandao:    executionPayload.ExecutionPayload.PrevRandao[:],
		BaseFeePerGas: uint256ToIntToByteSlice(executionPayload.ExecutionPayload.BaseFeePerGas),
		FeeRecipient:  executionPayload.ExecutionPayload.FeeRecipient[:],
		BlockHash:     executionPayload.ExecutionPayload.BlockHash[:],
		ExtraData:     executionPayload.ExecutionPayload.ExtraData,
		BlockNumber:   executionPayload.ExecutionPayload.BlockNumber,
		GasLimit:      executionPayload.ExecutionPayload.GasLimit,
		Timestamp:     executionPayload.ExecutionPayload.Timestamp,
		GasUsed:       executionPayload.ExecutionPayload.GasUsed,
		Transactions:  transactions,
		Withdrawals:   withdrawals,
		BlobGasUsed:   executionPayload.ExecutionPayload.BlobGasUsed,
		ExcessBlobGas: executionPayload.ExecutionPayload.ExcessBlobGas,
	}
	BlobsBundle := convertBlobBundleToProto(executionPayload.BlobsBundle)
	return &relay_grpc.ExecutionPayloadAndBlobsBundle{
		ExecutionPayload: ExecutionPayloadUncompressed,
		BlobsBundle:      BlobsBundle,
	}
}

// Add Commitments, Proofs, Data to BlobsBundle
func convertBlobBundleToProto(blobBundle *builderApiDeneb.BlobsBundle) *relay_grpc.BlobsBundle {
	protoBlobsBundle := &relay_grpc.BlobsBundle{
		Commitments: make([][]byte, len(blobBundle.Commitments)),
		Proofs:      make([][]byte, len(blobBundle.Proofs)),
		Blobs:       make([][]byte, len(blobBundle.Blobs)),
	}

	for i := range blobBundle.Commitments {
		protoBlobsBundle.Commitments[i] = blobBundle.Commitments[i][:]
	}

	for i := range blobBundle.Proofs {
		protoBlobsBundle.Proofs[i] = blobBundle.Proofs[i][:]
	}

	for i := range blobBundle.Blobs {
		protoBlobsBundle.Blobs[i] = blobBundle.Blobs[i][:]
	}

	return protoBlobsBundle
}

// DenebEnrichBlockRequest represents a request to enrich a block in Deneb.
type DenebEnrichBlockRequest struct {
	UUID                  string
	PayloadBundle         *builderApiDeneb.ExecutionPayloadAndBlobsBundle
	BidTrace              *builderApiV1.BidTrace
	ParentBeaconBlockRoot common.Hash
}

// ExecutableDataToExecutionPayloadV3 converts executable data to an execution payload V3.
func ExecutableDataToExecutionPayloadV3(data *engine.ExecutableData) (*deneb.ExecutionPayload, error) {
	transactionData := make([]bellatrix.Transaction, len(data.Transactions))
	for i, tx := range data.Transactions {
		transactionData[i] = bellatrix.Transaction(tx)
	}

	withdrawalData := make([]*capella.Withdrawal, len(data.Withdrawals))
	for i, withdrawal := range data.Withdrawals {
		withdrawalData[i] = &capella.Withdrawal{
			Index:          capella.WithdrawalIndex(withdrawal.Index),
			ValidatorIndex: phase0.ValidatorIndex(withdrawal.Validator),
			Address:        bellatrix.ExecutionAddress(withdrawal.Address),
			Amount:         phase0.Gwei(withdrawal.Amount),
		}
	}

	return &deneb.ExecutionPayload{
		ParentHash:    [32]byte(data.ParentHash),
		FeeRecipient:  [20]byte(data.FeeRecipient),
		StateRoot:     [32]byte(data.StateRoot),
		ReceiptsRoot:  [32]byte(data.ReceiptsRoot),
		LogsBloom:     types.BytesToBloom(data.LogsBloom),
		PrevRandao:    [32]byte(data.Random),
		BlockNumber:   data.Number,
		GasLimit:      data.GasLimit,
		GasUsed:       data.GasUsed,
		Timestamp:     data.Timestamp,
		ExtraData:     data.ExtraData,
		BaseFeePerGas: uint256.MustFromBig(data.BaseFeePerGas),
		BlockHash:     [32]byte(data.BlockHash),
		Transactions:  transactionData,
		Withdrawals:   withdrawalData,
		BlobGasUsed:   *data.BlobGasUsed,
		ExcessBlobGas: *data.ExcessBlobGas,
	}, nil
}

// DenebRequestToProtoRequest converts a Deneb request to a proto request.
func DenebRequestToProtoRequest(request *DenebEnrichBlockRequest) (*relay_grpc.EnrichBlockRequest, error) {
	transactions := make([]*relay_grpc.Transaction, len(request.PayloadBundle.ExecutionPayload.Transactions))
	for i, tx := range request.PayloadBundle.ExecutionPayload.Transactions {
		transactions[i] = &relay_grpc.Transaction{
			RawData: tx,
		}
	}

	withdrawals := make([]*relay_grpc.Withdrawal, len(request.PayloadBundle.ExecutionPayload.Withdrawals))
	for i, withdrawal := range request.PayloadBundle.ExecutionPayload.Withdrawals {
		withdrawals[i] = &relay_grpc.Withdrawal{
			ValidatorIndex: uint64(withdrawal.ValidatorIndex),
			Index:          uint64(withdrawal.Index),
			Amount:         uint64(withdrawal.Amount),
			Address:        withdrawal.Address[:],
		}
	}

	return &relay_grpc.EnrichBlockRequest{
		Uuid: request.UUID,
		ExecutionPayloadAndBlobsBundle: &relay_grpc.ExecutionPayloadAndBlobsBundle{
			ExecutionPayload: &relay_grpc.ExecutionPayloadUncompressed{
				ParentHash:    request.PayloadBundle.ExecutionPayload.ParentHash[:],
				StateRoot:     request.PayloadBundle.ExecutionPayload.StateRoot[:],
				ReceiptsRoot:  request.PayloadBundle.ExecutionPayload.ReceiptsRoot[:],
				LogsBloom:     request.PayloadBundle.ExecutionPayload.LogsBloom[:],
				PrevRandao:    request.PayloadBundle.ExecutionPayload.PrevRandao[:],
				BaseFeePerGas: uint256ToIntToByteSlice(request.PayloadBundle.ExecutionPayload.BaseFeePerGas),
				FeeRecipient:  request.PayloadBundle.ExecutionPayload.FeeRecipient[:],
				BlockHash:     request.PayloadBundle.ExecutionPayload.BlockHash[:],
				ExtraData:     request.PayloadBundle.ExecutionPayload.ExtraData,
				BlockNumber:   request.PayloadBundle.ExecutionPayload.BlockNumber,
				GasLimit:      request.PayloadBundle.ExecutionPayload.GasLimit,
				Timestamp:     request.PayloadBundle.ExecutionPayload.Timestamp,
				GasUsed:       request.PayloadBundle.ExecutionPayload.GasUsed,
				Transactions:  transactions,
				Withdrawals:   withdrawals,
				BlobGasUsed:   request.PayloadBundle.ExecutionPayload.BlobGasUsed,
				ExcessBlobGas: request.PayloadBundle.ExecutionPayload.ExcessBlobGas,
			},
			BlobsBundle: DenebBlobsBundleToProtoBlobsBundle(request.PayloadBundle.BlobsBundle),
		},
		BidTrace: &relay_grpc.BidTrace{
			Slot:                 request.BidTrace.Slot,
			ParentHash:           request.BidTrace.ParentHash[:],
			BlockHash:            request.BidTrace.BlockHash[:],
			BuilderPubkey:        request.BidTrace.BuilderPubkey[:],
			ProposerPubkey:       request.BidTrace.ProposerPubkey[:],
			ProposerFeeRecipient: request.BidTrace.ProposerFeeRecipient[:],
			GasLimit:             request.BidTrace.GasLimit,
			GasUsed:              request.BidTrace.GasUsed,
			Value:                request.BidTrace.Value.Hex(),
		},
		ParentBeaconRoot: request.ParentBeaconBlockRoot[:],
	}, nil
}

// ProtoRequestToDenebRequest converts a proto request to a Deneb request.
func ProtoRequestToDenebRequest(request *relay_grpc.EnrichBlockRequest) (*DenebEnrichBlockRequest, error) {
	// Add initial nil checks
	if request == nil {
		return nil, fmt.Errorf("request is nil")
	}
	if request.ExecutionPayloadAndBlobsBundle == nil {
		return nil, fmt.Errorf("ExecutionPayloadAndBlobsBundle is nil")
	}
	if request.ExecutionPayloadAndBlobsBundle.ExecutionPayload == nil {
		return nil, fmt.Errorf("ExecutionPayload is nil")
	}
	if request.BidTrace == nil {
		return nil, fmt.Errorf("BidTrace is nil")
	}

	transactions := make([]bellatrix.Transaction, len(request.ExecutionPayloadAndBlobsBundle.ExecutionPayload.Transactions))
	for index, tx := range request.ExecutionPayloadAndBlobsBundle.ExecutionPayload.Transactions {
		transactions[index] = tx.RawData
	}

	withdrawals := make([]*capella.Withdrawal, len(request.ExecutionPayloadAndBlobsBundle.ExecutionPayload.Withdrawals))
	for index, withdrawal := range request.ExecutionPayloadAndBlobsBundle.ExecutionPayload.Withdrawals {
		withdrawals[index] = &capella.Withdrawal{
			ValidatorIndex: phase0.ValidatorIndex(withdrawal.ValidatorIndex),
			Index:          capella.WithdrawalIndex(withdrawal.Index),
			Amount:         phase0.Gwei(withdrawal.Amount),
			Address:        b20(withdrawal.Address),
		}
	}

	// BlobsBundle
	blobsBundle := &builderApiDeneb.BlobsBundle{
		Commitments: make([]consensus.KZGCommitment, len(request.ExecutionPayloadAndBlobsBundle.BlobsBundle.Commitments)),
		Proofs:      make([]consensus.KZGProof, len(request.ExecutionPayloadAndBlobsBundle.BlobsBundle.Proofs)),
		Blobs:       make([]consensus.Blob, len(request.ExecutionPayloadAndBlobsBundle.BlobsBundle.Blobs)),
	}
	for index, commitment := range request.ExecutionPayloadAndBlobsBundle.BlobsBundle.Commitments {
		copy(blobsBundle.Commitments[index][:], commitment)
	}

	for index, proof := range request.ExecutionPayloadAndBlobsBundle.BlobsBundle.Proofs {
		copy(blobsBundle.Proofs[index][:], proof)
	}

	for index, blob := range request.ExecutionPayloadAndBlobsBundle.BlobsBundle.Blobs {
		copy(blobsBundle.Blobs[index][:], blob)
	}

	// Convert BidTrace.Value from string to *uint256.Int
	value, err := uint256.FromHex(request.BidTrace.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to convert deneb block value %s to uint256: %s", request.BidTrace.Value, err.Error())
	}

	return &DenebEnrichBlockRequest{
		UUID: request.Uuid,
		PayloadBundle: &builderApiDeneb.ExecutionPayloadAndBlobsBundle{
			ExecutionPayload: &deneb.ExecutionPayload{
				ParentHash:    b32(request.ExecutionPayloadAndBlobsBundle.ExecutionPayload.ParentHash),
				StateRoot:     b32(request.ExecutionPayloadAndBlobsBundle.ExecutionPayload.StateRoot),
				ReceiptsRoot:  b32(request.ExecutionPayloadAndBlobsBundle.ExecutionPayload.ReceiptsRoot),
				LogsBloom:     b256(request.ExecutionPayloadAndBlobsBundle.ExecutionPayload.LogsBloom),
				PrevRandao:    b32(request.ExecutionPayloadAndBlobsBundle.ExecutionPayload.PrevRandao),
				BaseFeePerGas: byteSliceToUint256Int(request.ExecutionPayloadAndBlobsBundle.ExecutionPayload.BaseFeePerGas),
				FeeRecipient:  b20(request.ExecutionPayloadAndBlobsBundle.ExecutionPayload.FeeRecipient),
				BlockHash:     b32(request.ExecutionPayloadAndBlobsBundle.ExecutionPayload.BlockHash),
				ExtraData:     request.ExecutionPayloadAndBlobsBundle.ExecutionPayload.ExtraData,
				BlockNumber:   request.ExecutionPayloadAndBlobsBundle.ExecutionPayload.BlockNumber,
				GasLimit:      request.ExecutionPayloadAndBlobsBundle.ExecutionPayload.GasLimit,
				Timestamp:     request.ExecutionPayloadAndBlobsBundle.ExecutionPayload.Timestamp,
				GasUsed:       request.ExecutionPayloadAndBlobsBundle.ExecutionPayload.GasUsed,
				Transactions:  transactions,
				Withdrawals:   withdrawals,
				BlobGasUsed:   request.ExecutionPayloadAndBlobsBundle.ExecutionPayload.BlobGasUsed,
				ExcessBlobGas: request.ExecutionPayloadAndBlobsBundle.ExecutionPayload.ExcessBlobGas,
			},
			BlobsBundle: blobsBundle,
		},
		BidTrace: &builderApiV1.BidTrace{
			Slot:                 request.BidTrace.Slot,
			ParentHash:           b32(request.BidTrace.ParentHash),
			BlockHash:            b32(request.BidTrace.BlockHash),
			BuilderPubkey:        b48(request.BidTrace.BuilderPubkey),
			ProposerPubkey:       b48(request.BidTrace.ProposerPubkey),
			ProposerFeeRecipient: b20(request.BidTrace.ProposerFeeRecipient),
			GasLimit:             request.BidTrace.GasLimit,
			GasUsed:              request.BidTrace.GasUsed,
			Value:                value,
		},
		ParentBeaconBlockRoot: common.BytesToHash(request.ParentBeaconRoot),
	}, nil
}

// DenebBlobsBundleToProtoBlobsBundle converts a Deneb blobs bundle to a proto blobs bundle.
func DenebBlobsBundleToProtoBlobsBundle(blobBundle *builderApiDeneb.BlobsBundle) *relay_grpc.BlobsBundle {
	protoBlobsBundle := &relay_grpc.BlobsBundle{
		Commitments: make([][]byte, len(blobBundle.Commitments)),
		Proofs:      make([][]byte, len(blobBundle.Proofs)),
		Blobs:       make([][]byte, len(blobBundle.Blobs)),
	}

	for i := range blobBundle.Commitments {
		protoBlobsBundle.Commitments[i] = blobBundle.Commitments[i][:]
	}

	for i := range blobBundle.Proofs {
		protoBlobsBundle.Proofs[i] = blobBundle.Proofs[i][:]
	}

	for i := range blobBundle.Blobs {
		protoBlobsBundle.Blobs[i] = blobBundle.Blobs[i][:]
	}

	return protoBlobsBundle
}

// HeaderToProtoHeader converts a header to a proto header.
func HeaderToProtoHeader(header *deneb.ExecutionPayloadHeader) *relay_grpc.ExecutionPayloadHeader {
	if header == nil {
		return &relay_grpc.ExecutionPayloadHeader{}
	}

	return &relay_grpc.ExecutionPayloadHeader{
		ParentHash:       header.ParentHash[:],
		FeeRecipient:     header.FeeRecipient[:],
		StateRoot:        header.StateRoot[:],
		ReceiptsRoot:     header.ReceiptsRoot[:],
		LogsBloom:        header.LogsBloom[:],
		PrevRandao:       header.PrevRandao[:],
		BlockNumber:      header.BlockNumber,
		GasLimit:         header.GasLimit,
		GasUsed:          header.GasUsed,
		Timestamp:        header.Timestamp,
		ExtraData:        header.ExtraData,
		BaseFeePerGas:    uint256ToIntToByteSlice(header.BaseFeePerGas),
		BlockHash:        header.BlockHash[:],
		TransactionsRoot: header.TransactionsRoot[:],
		WithdrawalsRoot:  header.WithdrawalsRoot[:],
		BlobGasUsed:      header.BlobGasUsed,
		ExcessBlobGas:    header.ExcessBlobGas,
	}
}

// CommitmentsToProtoCommitments converts commitments to proto commitments.
func CommitmentsToProtoCommitments(commitments []deneb.KZGCommitment) [][]byte {
	if len(commitments) == 0 {
		return [][]byte{}
	}

	protoCommitments := make([][]byte, len(commitments))
	for i, commitment := range commitments {
		protoCommitments[i] = commitment[:]
	}
	return protoCommitments
}

// Helper functions

// b20 converts a byte slice to a [20]byte.
func b20(b []byte) [20]byte {
	var out [20]byte
	copy(out[:], b)
	return out
}

// b32 converts a byte slice to a [32]byte.
func b32(b []byte) [32]byte {
	var out [32]byte
	copy(out[:], b)
	return out
}

// b48 converts a byte slice to a [48]byte.
func b48(b []byte) [48]byte {
	var out [48]byte
	copy(out[:], b)
	return out
}

// b96 converts a byte slice to a [96]byte.
func b96(b []byte) [96]byte {
	var out [96]byte
	copy(out[:], b)
	return out
}

// b256 converts a byte slice to a [256]byte.
func b256(b []byte) [256]byte {
	var out [256]byte
	copy(out[:], b)
	return out
}

// uint256ToBytes converts a *uint256.Int to a byte slice.
func uint256ToBytes(u *uint256.Int) []byte {
	if u == nil {
		return nil
	}
	return u.Bytes()
}

// bytesToUint256 converts a byte slice to a *uint256.Int.
func bytesToUint256(b []byte) *uint256.Int {
	u := new(uint256.Int)
	u.SetBytes(b)
	return u
}

// uint256ToIntToByteSlice converts a *uint256.Int to a byte slice.
func uint256ToIntToByteSlice(u *uint256.Int) []byte {
	if u == nil {
		return nil
	}
	// Convert the uint256.Int to a byte slice.
	// The Bytes method returns the absolute value as a big-endian byte slice.
	return u.Bytes()
}

// byteSliceToUint256Int converts a byte slice to a *uint256.Int.
func byteSliceToUint256Int(b []byte) *uint256.Int {
	u256, _ := uint256.FromBig(new(big.Int).SetBytes(b))
	return u256
}

func DenebPayloadToProtoPayload(payload *deneb.ExecutionPayload) *relay_grpc.ExecutionPayloadUncompressed {
	transactions := make([]*relay_grpc.Transaction, len(payload.Transactions))
	for i, tx := range payload.Transactions {
		transactions[i] = &relay_grpc.Transaction{
			RawData: tx,
		}
	}

	withdrawals := make([]*relay_grpc.Withdrawal, len(payload.Withdrawals))
	for i, withdrawal := range payload.Withdrawals {
		withdrawals[i] = &relay_grpc.Withdrawal{
			ValidatorIndex: uint64(withdrawal.ValidatorIndex),
			Index:          uint64(withdrawal.Index),
			Amount:         uint64(withdrawal.Amount),
			Address:        withdrawal.Address[:],
		}
	}

	protoPayload := &relay_grpc.ExecutionPayloadUncompressed{
		ParentHash:    payload.ParentHash[:],
		FeeRecipient:  payload.FeeRecipient[:],
		StateRoot:     payload.StateRoot[:],
		ReceiptsRoot:  payload.ReceiptsRoot[:],
		LogsBloom:     payload.LogsBloom[:],
		PrevRandao:    payload.PrevRandao[:],
		BlockNumber:   payload.BlockNumber,
		GasLimit:      payload.GasLimit,
		GasUsed:       payload.GasUsed,
		Timestamp:     payload.Timestamp,
		ExtraData:     payload.ExtraData,
		BaseFeePerGas: uint256ToIntToByteSlice(payload.BaseFeePerGas),
		BlockHash:     payload.BlockHash[:],
		Transactions:  transactions,
		Withdrawals:   withdrawals,
		BlobGasUsed:   payload.BlobGasUsed,
		ExcessBlobGas: payload.ExcessBlobGas,
	}

	return protoPayload
}
