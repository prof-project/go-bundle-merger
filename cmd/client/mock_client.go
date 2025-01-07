// Package main provides a mock client for testing purposes.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	relay_grpc "github.com/bloXroute-Labs/relay-grpc"
	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	beaconConsensus "github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/miner"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
	"github.com/prof-project/go-bundle-merger/utils"
	"google.golang.org/grpc"
)

var (
	testKey, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	testAddr   = crypto.PubkeyToAddress(testKey.PublicKey)

	// Validator
	testValidatorKey, _ = crypto.HexToECDSA("28c3cd61b687fdd03488e167a5d84f50269df2a4c29a2cfb1390903aa775c5d0")
	testValidatorAddr   = crypto.PubkeyToAddress(testValidatorKey.PublicKey)

	// Builder
	testBuilderKeyHex = "0bfbbbc68fefd990e61ba645efb84e0a62e94d5fff02c9b1da8eb45fea32b4e0"
	testBuilderKey, _ = crypto.HexToECDSA(testBuilderKeyHex)
	testBuilderAddr   = crypto.PubkeyToAddress(testBuilderKey.PublicKey)

	// Balance
	testBalance = big.NewInt(2e18)

	// EVM code that generates a log when the contract is created.
	logCode = common.Hex2Bytes("60606040525b7f24ec1d3ff24c2f6ff210738839dbc339cd45a5294d85c79361016243157aae7b60405180905060405180910390a15b600a8060416000396000f360606040526008565b00")
)

func main() {
	// Set up a gRPC client connection to the bundle merger server.
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Failed to connect to gRPC server: %v", err)
	}
	defer conn.Close()

	client := relay_grpc.NewEnricherClient(conn)

	// Start the Ethereum service.
	n, ethservice := startEthService()
	ethservice.Merger().ReachTTD()
	defer n.Close()

	// Create a sample EnrichBlockRequest.
	ctx := context.Background()

	// Start the EnrichBlock stream.
	stream, err := client.EnrichBlockStream(ctx)
	if err != nil {
		log.Fatalf("Failed to start EnrichBlock stream: %v", err)
	}

	parent := ethservice.BlockChain().CurrentHeader()

	// Set etherbase.
	ethservice.APIBackend.Miner().SetEtherbase(testBuilderAddr)

	statedb, _ := ethservice.BlockChain().StateAt(parent.Root)
	nonce := statedb.GetNonce(testAddr)

	// Create and add transactions to the txpool.
	tx1, _ := types.SignTx(
		types.NewTransaction(nonce, common.Address{0x16}, big.NewInt(10), 21000, big.NewInt(2*params.InitialBaseFee), nil),
		types.LatestSigner(ethservice.BlockChain().Config()), testKey)

	// Add the transaction to the txpool.
	ethservice.TxPool().Add([]*types.Transaction{tx1}, true, true, false)

	cc, _ := types.SignTx(
		types.NewContractCreation(nonce+1, new(big.Int), 1000000, big.NewInt(2*params.InitialBaseFee), logCode),
		types.LatestSigner(ethservice.BlockChain().Config()), testKey)

	ethservice.TxPool().Add([]*types.Transaction{cc}, true, true, false)

	baseFee := eip1559.CalcBaseFee(params.AllEthashProtocolChanges, parent)
	tx2, _ := types.SignTx(
		types.NewTransaction(nonce+2, testAddr, big.NewInt(10), 21000, baseFee, nil),
		types.LatestSigner(ethservice.BlockChain().Config()), testKey)

	ethservice.TxPool().Add([]*types.Transaction{tx2}, true, true, false)

	withdrawals := []*types.Withdrawal{
		{
			Index:     0,
			Validator: 1,
			Amount:    100,
			Address:   testAddr,
		},
		{
			Index:     1,
			Validator: 1,
			Amount:    100,
			Address:   testAddr,
		},
	}

	execData, err := assembleBlock(parent.Hash(), &engine.PayloadAttributes{
		Timestamp:             parent.Time + 5,
		Withdrawals:           withdrawals,
		SuggestedFeeRecipient: testValidatorAddr,
		BeaconRoot:            &common.Hash{42},
	}, ethservice)
	if err != nil {
		log.Fatalf("Failed to assemble block: %v", err)
	}

	payload, err := utils.ExecutableDataToExecutionPayloadV3(execData)
	if err != nil {
		log.Fatalf("Failed to convert ExecutableData to ExecutionPayloadV3: %v", err)
	}

	proposerAddr := bellatrix.ExecutionAddress{}
	copy(proposerAddr[:], testValidatorAddr.Bytes())

	denebRequest := &utils.DenebEnrichBlockRequest{
		Uuid: "test-uuid",
		PayloadBundle: &builderApiDeneb.ExecutionPayloadAndBlobsBundle{
			ExecutionPayload: payload,
			BlobsBundle: &builderApiDeneb.BlobsBundle{
				Commitments: make([]deneb.KZGCommitment, 0),
				Proofs:      make([]deneb.KZGProof, 0),
				Blobs:       make([]deneb.Blob, 0),
			},
		},
		BidTrace: &builderApiV1.BidTrace{
			ParentHash:           phase0.Hash32(execData.ParentHash),
			BlockHash:            phase0.Hash32(execData.BlockHash),
			ProposerFeeRecipient: proposerAddr,
			GasLimit:             execData.GasLimit,
			GasUsed:              execData.GasUsed,
			// This value is actual profit + 1, validation should fail.
			Value: uint256.NewInt(132912184722469),
		},
		ParentBeaconBlockRoot: common.Hash{42},
	}

	// Convert to gRPC compatible request.
	protoRequest, err := utils.DenebRequestToProtoRequest(denebRequest)
	if err != nil {
		log.Fatalf("Failed to convert DenebRequest to ProtoRequest: %v", err)
	}

	// Send the request.
	if err := stream.Send(protoRequest); err != nil {
		log.Fatalf("Failed to send request: %v", err)
	}

	// Receive the response.
	resp, err := stream.Recv()
	if err != nil {
		log.Fatalf("Failed to receive response: %v", err)
	}

	// Print the response.
	fmt.Printf("Response: %+v\n", resp)

	// Close the stream.
	if err := stream.CloseSend(); err != nil {
		log.Fatalf("Failed to close stream: %v", err)
	}
}

func startEthService() (*node.Node, *eth.Ethereum) {
	// Set up a simulated backend.
	genesis, blocks := generateMergeChain(10, true)

	// Set Cancun time to last block + 5 seconds.
	cancunTime := blocks[len(blocks)-1].Time() + 5
	genesis.Config.ShanghaiTime = &cancunTime
	genesis.Config.CancunTime = &cancunTime
	os.Setenv("BUILDER_TX_SIGNING_KEY", testBuilderKeyHex)

	n, err := node.New(&node.Config{
		P2P: p2p.Config{
			ListenAddr:  "0.0.0.0:0",
			NoDiscovery: true,
			MaxPeers:    25,
		},
	})
	if err != nil {
		log.Fatalf("Can't create node: %v", err)
	}

	ethcfg := &ethconfig.Config{
		Genesis:        genesis,
		SyncMode:       downloader.FullSync,
		TrieTimeout:    time.Minute,
		TrieDirtyCache: 256,
		TrieCleanCache: 256,
	}
	ethservice, err := eth.New(n, ethcfg)
	if err != nil {
		log.Fatalf("Can't create eth service: %v", err)
	}
	if err := n.Start(); err != nil {
		log.Fatalf("Can't start node: %v", err)
	}
	if _, err := ethservice.BlockChain().InsertChain(blocks); err != nil {
		n.Close()
		log.Fatalf("Can't import test blocks: %v", err)
	}
	time.Sleep(500 * time.Millisecond) // Give txpool enough time to consume head event.

	ethservice.SetEtherbase(testAddr)
	ethservice.SetSynced()
	return n, ethservice
}

func assembleBlock(parentHash common.Hash, params *engine.PayloadAttributes, ethservice *eth.Ethereum) (*engine.ExecutableData, error) {
	args := &miner.BuildPayloadArgs{
		Parent:       parentHash,
		Timestamp:    params.Timestamp,
		FeeRecipient: params.SuggestedFeeRecipient,
		GasLimit:     params.GasLimit,
		Random:       params.Random,
		Withdrawals:  params.Withdrawals,
		BeaconRoot:   params.BeaconRoot,
	}

	payload, err := ethservice.Miner().BuildPayload(args)
	if err != nil {
		return nil, err
	}

	if payload := payload.ResolveFull(); payload != nil {
		return payload.ExecutionPayload, nil
	}

	return nil, errors.New("Payload did not resolve")
}

func generateMergeChain(n int, merged bool) (*core.Genesis, []*types.Block) {
	config := *params.AllEthashProtocolChanges
	engine := consensus.Engine(beaconConsensus.New(ethash.NewFaker()))
	if merged {
		config.TerminalTotalDifficulty = common.Big0
		config.TerminalTotalDifficultyPassed = true
		engine = beaconConsensus.NewFaker()
	}
	genesis := &core.Genesis{
		Config: &config,
		Alloc: types.GenesisAlloc{
			testAddr: {Balance: testBalance},
			params.BeaconRootsStorageAddress: {
				Balance: common.Big0,
				Code:    common.Hex2Bytes("3373fffffffffffffffffffffffffffffffffffffffe14604457602036146024575f5ffd5b620180005f350680545f35146037575f5ffd5b6201800001545f5260205ff35b6201800042064281555f359062018000015500"),
			},
		},
		ExtraData:  []byte("test genesis"),
		Timestamp:  9000,
		BaseFee:    big.NewInt(params.InitialBaseFee),
		Difficulty: big.NewInt(0),
	}
	testNonce := uint64(0)
	generate := func(_ int, g *core.BlockGen) {
		g.OffsetTime(5)
		g.SetExtra([]byte("test"))
		tx, _ := types.SignTx(
			types.NewTransaction(testNonce, common.HexToAddress("0x9a9070028361F7AAbeB3f2F2Dc07F82C4a98A02a"), big.NewInt(1), params.TxGas, big.NewInt(params.InitialBaseFee*2), nil),
			types.LatestSigner(&config), testKey)
		g.AddTx(tx)
		testNonce++
	}
	_, blocks, _ := core.GenerateChainWithGenesis(genesis, engine, n, generate)

	if !merged {
		totalDifficulty := big.NewInt(0)
		for _, b := range blocks {
			totalDifficulty.Add(totalDifficulty, b.Difficulty())
		}
		config.TerminalTotalDifficulty = totalDifficulty
	}

	return genesis, blocks
}
