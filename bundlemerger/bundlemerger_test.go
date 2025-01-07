package bundlemerger

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strconv"
	"testing"
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
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/holiman/uint256"
	"github.com/prof-project/go-bundle-merger/utils"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

var (
	testKey, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	testAddr   = crypto.PubkeyToAddress(testKey.PublicKey)

	// validator
	testValidatorKey, _ = crypto.HexToECDSA("28c3cd61b687fdd03488e167a5d84f50269df2a4c29a2cfb1390903aa775c5d0")
	testValidatorAddr   = crypto.PubkeyToAddress(testValidatorKey.PublicKey)

	// builder
	testBuilderKeyHex = "0bfbbbc68fefd990e61ba645efb84e0a62e94d5fff02c9b1da8eb45fea32b4e0"
	testBuilderKey, _ = crypto.HexToECDSA(testBuilderKeyHex)
	testBuilderAddr   = crypto.PubkeyToAddress(testBuilderKey.PublicKey)

	// balance
	testBalance = big.NewInt(2e18)

	// This EVM code generates a log when the contract is created.
	logCode = common.Hex2Bytes("60606040525b7f24ec1d3ff24c2f6ff210738839dbc339cd45a5294d85c79361016243157aae7b60405180905060405180910390a15b600a8060416000396000f360606040526008565b00")
)

// TestEnrichBlock tests the EnrichBlock RPC method
// NOTE
// This assumes a running builder at 8545, as simulation is currently done via JSON-RPC
// Hence, this test is not fully self-contained and will fail if the builder is not running, e.g. in Kurtosis
func TestEnrichBlock(t *testing.T) {
	// Set up a simulated backend
	genesis, blocks := generateMergeChain(10, true)

	// Set cancun time to last block + 5 seconds
	cancunTime := blocks[len(blocks)-1].Time() + 5
	genesis.Config.ShanghaiTime = &cancunTime
	genesis.Config.CancunTime = &cancunTime
	os.Setenv("BUILDER_TX_SIGNING_KEY", testBuilderKeyHex)

	n, ethservice := startEthService(t, genesis, blocks)
	ethservice.Merger().ReachTTD()
	defer n.Close()

	// Create RPC client for builder API
	clientEth, err := rpc.Dial("http://localhost:8545")
	require.NoError(t, err)

	// Create a new BundleMergerServer with the required options
	bundleService := NewBundleServiceServer()
	server := NewBundleMergerServerEth(ServerOpts{
		BundleService: bundleService,
		ExecClient:    clientEth,
	})

	// Set up a buffer connection for gRPC
	lis := bufconn.Listen(1024 * 1024)
	s := grpc.NewServer()
	relay_grpc.RegisterEnricherServer(s, server)
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Errorf("Server exited with error: %v", err)
		}
	}()

	// Set up a client connection to the server
	ctx := context.Background()
	conn, err := grpc.DialContext(
		context.Background(),
		"bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	defer conn.Close()

	client := relay_grpc.NewEnricherClient(conn)

	// Start the EnrichBlock stream
	stream, err := client.EnrichBlockStream(ctx)
	require.NoError(t, err)

	// Create a sample EnrichBlockRequest
	parent := ethservice.BlockChain().CurrentHeader()

	ethservice.Miner().SetEtherbase(testBuilderAddr)

	statedb, _ := ethservice.BlockChain().StateAt(parent.Root)
	nonce := statedb.GetNonce(testAddr)

	tx1, _ := types.SignTx(types.NewTransaction(nonce, common.Address{0x16}, big.NewInt(10), 21000, big.NewInt(2*params.InitialBaseFee), nil), types.LatestSigner(ethservice.BlockChain().Config()), testKey)
	ethservice.TxPool().Add([]*types.Transaction{tx1}, true, true, false)

	cc, _ := types.SignTx(types.NewContractCreation(nonce+1, new(big.Int), 1000000, big.NewInt(2*params.InitialBaseFee), logCode), types.LatestSigner(ethservice.BlockChain().Config()), testKey)
	ethservice.TxPool().Add([]*types.Transaction{cc}, true, true, false)

	// Calculate total gas consumed by tx1 and tx2
	totalGas := tx1.Gas() + cc.Gas()
	fmt.Printf("Total gas consumed by tx1, cc, cc2 and tx2: %d\n", totalGas)

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

	execData, err := assembleBlock(server, ethservice, parent.Hash(), &engine.PayloadAttributes{
		Timestamp:             parent.Time + 5,
		Withdrawals:           withdrawals,
		SuggestedFeeRecipient: testValidatorAddr,
		BeaconRoot:            &common.Hash{42},
	})
	require.NoError(t, err)
	require.EqualValues(t, len(execData.Withdrawals), 2)
	require.EqualValues(t, len(execData.Transactions), 3)

	// Add this: Wait for the block to be processed
	time.Sleep(500 * time.Millisecond)

	// Verify the parent block exists
	block := ethservice.BlockChain().GetBlockByHash(parent.Hash())
	require.NotNil(t, block, "Parent block not found in blockchain")

	payload, err := utils.ExecutableDataToExecutionPayloadV3(execData)
	require.NoError(t, err)

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
		BidTrace: &builderApiV1.BidTrace{ // Use BidTrace instead of ProfBundle
			ParentHash:           phase0.Hash32(execData.ParentHash),
			BlockHash:            phase0.Hash32(execData.BlockHash),
			ProposerFeeRecipient: proposerAddr,
			GasLimit:             execData.GasLimit,
			GasUsed:              execData.GasUsed,
			// This value is actual profit + 1, validation should fail
			Value: uint256.NewInt(132912184722469),
		},
		ParentBeaconBlockRoot: common.Hash{42},
	}

	// Convert to gRPC compatible request
	protoRequest := utils.ExecutionPayloadToProtoEnrichBlockRequest(
		denebRequest.Uuid,
		denebRequest.PayloadBundle,
		*denebRequest.BidTrace,
		phase0.Root(denebRequest.ParentBeaconBlockRoot),
	)

	require.NoError(t, err)

	// Filling transactions into the PROF pool
	tx2, _ := types.SignTx(types.NewTransaction(nonce+2, common.Address{0x16}, big.NewInt(10), 21000, big.NewInt(2*params.InitialBaseFee), nil), types.LatestSigner(ethservice.BlockChain().Config()), testKey)
	ethservice.TxPool().Add([]*types.Transaction{tx1}, true, true, false)

	cc2, _ := types.SignTx(types.NewContractCreation(nonce+3, new(big.Int), 1000000, big.NewInt(2*params.InitialBaseFee), logCode), types.LatestSigner(ethservice.BlockChain().Config()), testKey)

	// Add a bundle to the pool
	bundle := &TxBundle{
		BlockNumber: "0x" + strconv.FormatUint(parent.Number.Uint64()+1, 16),
		Txs:         []*types.Transaction{tx2, cc2},
	}
	err = server.pool.addBundle(bundle, true)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	// Measure time for sending and receiving
	start := time.Now()

	// Send the request
	err = stream.Send(&protoRequest)
	require.NoError(t, err)

	// Receive the response
	resp, err := stream.Recv()

	// Calculate elapsed time
	elapsed := time.Since(start)

	// Print the response and elapsed time
	fmt.Printf("Response: %+v\n", resp)
	fmt.Printf("Time taken: %v\n", elapsed)
	require.NoError(t, err)

	// Verify the response
	require.Equal(t, protoRequest.Uuid, resp.Uuid)
	require.NotEmpty(t, resp.ExecutionPayloadHeader)
	require.NotEmpty(t, resp.Value)
	require.NotEmpty(t, resp.KzgCommitment)

	// Close the stream
	err = stream.CloseSend()
	require.NoError(t, err)
}

// Helper functions from block-validation/api_test.go

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
			testAddr:                         {Balance: testBalance},
			params.BeaconRootsStorageAddress: {Balance: common.Big0, Code: common.Hex2Bytes("3373fffffffffffffffffffffffffffffffffffffffe14604457602036146024575f5ffd5b620180005f350680545f35146037575f5ffd5b6201800001545f5260205ff35b6201800042064281555f359062018000015500")},
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
		tx, _ := types.SignTx(types.NewTransaction(testNonce, common.HexToAddress("0x9a9070028361F7AAbeB3f2F2Dc07F82C4a98A02a"), big.NewInt(1), params.TxGas, big.NewInt(params.InitialBaseFee*2), nil), types.LatestSigner(&config), testKey)
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

// startEthService creates a full node instance for testing.
func startEthService(t *testing.T, genesis *core.Genesis, blocks []*types.Block) (*node.Node, *eth.Ethereum) {
	t.Helper()

	n, err := node.New(&node.Config{
		P2P: p2p.Config{
			ListenAddr:  "0.0.0.0:0",
			NoDiscovery: true,
			MaxPeers:    25,
		},
		HTTPHost: "127.0.0.1",
		HTTPPort: 0,
		HTTPModules: []string{
			"eth",
			"net",
			"web3",
			"builder",
			"flashbots",
		},
		WSHost: "127.0.0.1",
		WSPort: 0,
		WSModules: []string{
			"admin",
			"engine",
			"net",
			"eth",
			"web3",
			"debug",
			"mev",
			"flashbots",
		},
	})
	if err != nil {
		t.Fatal("can't create node:", err)
	}

	ethcfg := &ethconfig.Config{Genesis: genesis, SyncMode: downloader.FullSync, TrieTimeout: time.Minute, TrieDirtyCache: 256, TrieCleanCache: 256}
	ethservice, err := eth.New(n, ethcfg)
	if err != nil {
		t.Fatal("can't create eth service:", err)
	}

	if err := n.Start(); err != nil {
		t.Fatal("can't start node:", err)
	}

	if _, err := ethservice.BlockChain().InsertChain(blocks); err != nil {
		n.Close()
		t.Fatal("can't import test blocks:", err)
	}

	time.Sleep(500 * time.Millisecond)
	ethservice.SetEtherbase(testAddr)
	ethservice.SetSynced()
	return n, ethservice
}

func assembleBlock(_ *Server, ethservice *eth.Ethereum, parentHash common.Hash, params *engine.PayloadAttributes) (*engine.ExecutableData, error) {
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

	return nil, errors.New("payload did not resolve")
}

func TestGetEnrichedPayload(t *testing.T) {
	// Set up a simulated backend (reuse the setup from TestEnrichBlock)
	genesis, blocks := generateMergeChain(10, true)
	cancunTime := blocks[len(blocks)-1].Time() + 5
	genesis.Config.ShanghaiTime = &cancunTime
	genesis.Config.CancunTime = &cancunTime
	os.Setenv("BUILDER_TX_SIGNING_KEY", testBuilderKeyHex)

	n, ethservice := startEthService(t, genesis, blocks)
	ethservice.Merger().ReachTTD()
	defer n.Close()

	// Create RPC client for builder API
	clientEth, err := rpc.Dial("http://localhost:8545")
	require.NoError(t, err)

	bundleService := NewBundleServiceServer()
	server := NewBundleMergerServerEth(ServerOpts{
		BundleService: bundleService,
		ExecClient:    clientEth,
	})

	// Set up a buffer connection for gRPC
	lis := bufconn.Listen(1024 * 1024)
	s := grpc.NewServer()
	relay_grpc.RegisterEnricherServer(s, server)
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Errorf("Server exited with error: %v", err)
		}
	}()

	// Set up a client connection to the server
	ctx := context.Background()
	conn, err := grpc.DialContext(
		context.Background(),
		"bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	defer conn.Close()

	client := relay_grpc.NewEnricherClient(conn)

	// Enrich a block first
	enrichBlockStream, err := client.EnrichBlockStream(ctx)
	require.NoError(t, err)

	// Create a sample EnrichBlockRequest
	parent := ethservice.BlockChain().CurrentHeader()

	ethservice.Miner().SetEtherbase(testBuilderAddr)

	statedb, _ := ethservice.BlockChain().StateAt(parent.Root)
	nonce := statedb.GetNonce(testAddr)

	tx1, _ := types.SignTx(types.NewTransaction(nonce, common.Address{0x16}, big.NewInt(10), 21000, big.NewInt(2*params.InitialBaseFee), nil), types.LatestSigner(ethservice.BlockChain().Config()), testKey)
	ethservice.TxPool().Add([]*types.Transaction{tx1}, true, true, false)

	cc, _ := types.SignTx(types.NewContractCreation(nonce+1, new(big.Int), 1000000, big.NewInt(2*params.InitialBaseFee), logCode), types.LatestSigner(ethservice.BlockChain().Config()), testKey)
	ethservice.TxPool().Add([]*types.Transaction{cc}, true, true, false)

	// Calculate total gas consumed by tx1 and cc
	totalGas := tx1.Gas() + cc.Gas()
	fmt.Printf("Total gas consumed by tx1 and cc: %d\n", totalGas)

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

	execData, err := assembleBlock(server, ethservice, parent.Hash(), &engine.PayloadAttributes{
		Timestamp:             parent.Time + 5,
		Withdrawals:           withdrawals,
		SuggestedFeeRecipient: testValidatorAddr,
		BeaconRoot:            &common.Hash{42},
	})
	require.NoError(t, err)
	require.EqualValues(t, len(execData.Withdrawals), 2)
	require.EqualValues(t, len(execData.Transactions), 3)

	// Add this: Wait for the block to be processed
	time.Sleep(500 * time.Millisecond)

	// Verify the parent block exists
	block := ethservice.BlockChain().GetBlockByHash(parent.Hash())
	require.NotNil(t, block, "Parent block not found in blockchain")

	payload, err := utils.ExecutableDataToExecutionPayloadV3(execData)
	require.NoError(t, err)

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
		BidTrace: &builderApiV1.BidTrace{ // Use BidTrace instead of ProfBundle
			ParentHash:           phase0.Hash32(execData.ParentHash),
			BlockHash:            phase0.Hash32(execData.BlockHash),
			ProposerFeeRecipient: proposerAddr,
			GasLimit:             execData.GasLimit,
			GasUsed:              execData.GasUsed,
			// This value is actual profit + 1, validation should fail
			Value: uint256.NewInt(132912184722469),
		},
		ParentBeaconBlockRoot: common.Hash{42},
	}

	// Convert to gRPC compatible request
	// protoRequest, err := utils.DenebRequestToProtoRequest(denebRequest)
	// Convert to gRPC compatible request
	// require.NoError(t, err)
	protoRequest := utils.ExecutionPayloadToProtoEnrichBlockRequest(
		denebRequest.Uuid,
		denebRequest.PayloadBundle,
		*denebRequest.BidTrace,
		phase0.Root(denebRequest.ParentBeaconBlockRoot),
	)

	// Filling transactions into the PROF pool
	tx2, _ := types.SignTx(types.NewTransaction(nonce+2, common.Address{0x16}, big.NewInt(10), 21000, big.NewInt(2*params.InitialBaseFee), nil), types.LatestSigner(ethservice.BlockChain().Config()), testKey)
	ethservice.TxPool().Add([]*types.Transaction{tx2}, true, true, false)

	cc2, _ := types.SignTx(types.NewContractCreation(nonce+3, new(big.Int), 1000000, big.NewInt(2*params.InitialBaseFee), logCode), types.LatestSigner(ethservice.BlockChain().Config()), testKey)

	// Add a bundle to the pool
	bundle := &TxBundle{
		BlockNumber: "0x" + strconv.FormatUint(parent.Number.Uint64()+1, 16),
		Txs:         []*types.Transaction{tx2, cc2},
	}
	err = server.pool.addBundle(bundle, true)
	require.NoError(t, err)

	// Measure time for sending and receiving
	start := time.Now()

	// Send the request
	err = enrichBlockStream.Send(&protoRequest)
	require.NoError(t, err)

	// Receive the response
	resp, err := enrichBlockStream.Recv()

	// Calculate elapsed time
	elapsed := time.Since(start)

	// Print the response and elapsed time
	fmt.Printf("Enrich Block Response: %+v\n", resp)
	fmt.Printf("Time taken for EnrichBlock: %v\n", elapsed)
	require.NoError(t, err)

	// Verify the EnrichBlock response
	require.Equal(t, protoRequest.Uuid, resp.Uuid)
	require.NotEmpty(t, resp.ExecutionPayloadHeader)
	require.NotEmpty(t, resp.Value)

	// Close the enrich block stream
	err = enrichBlockStream.CloseSend()
	require.NoError(t, err)

	// Allow some time for the server to process the enriched payload
	time.Sleep(500 * time.Millisecond)

	// After enriching the block, get the enriched payload
	getEnrichedPayloadReq := &relay_grpc.GetEnrichedPayloadRequest{
		Message: []byte(protoRequest.Uuid),
		// TODO - Add signature - verificaiton still to be added in utils and api
		Signature: []byte{},
	}

	enrichedPayloadResp, err := client.GetEnrichedPayload(ctx, getEnrichedPayloadReq)
	require.NoError(t, err)

	fmt.Printf("Enriched Payload Response: %+v\n", enrichedPayloadResp)

	// Verify the retrieved enriched payload
	require.NotNil(t, enrichedPayloadResp)

	// ToDo - Add more sanity checks for the returned Payload
	// require.Equal(t, common.BytesToHash(enrichedPayload.BlockHash[:]), common.BytesToHash(enrichedPayloadResp.ExecutionPayload.BlockHash))
	// require.Equal(t, enrichedPayload.Header, enrichedPayloadResp.ExecutionPayload.Header)
	// require.Equal(t, enrichedPayload.Value, enrichedPayloadResp.ExecutionPayload.Value)
	// require.Equal(t, enrichedPayload.GasUsed, enrichedPayloadResp.ExecutionPayload.GasUsed)
	// require.Equal(t, enrichedPayload.GasLimit, enrichedPayloadResp.ExecutionPayload.GasLimit)
	// require.Equal(t, enrichedPayload.Timestamp, enrichedPayloadResp.ExecutionPayload.Timestamp)
}
