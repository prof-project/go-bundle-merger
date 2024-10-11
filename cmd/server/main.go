package main

import (
    "log"
    "math/big"
    "time"

    "github.com/mdlayher/vsock"
    "google.golang.org/grpc"

    pb "github.com/prof-project/prof-grpc/go/profpb" 
    "github.com/prof-project/go-bundle-merger/bundlemerger" 
	"github.com/prof-project/go-bundle-merger/utils"   

    // Ethereum dependencies
    "github.com/ethereum/go-ethereum/beacon/engine"
    beaconConsensus "github.com/ethereum/go-ethereum/consensus/beacon"
    "github.com/ethereum/go-ethereum/consensus/ethash"
    "github.com/ethereum/go-ethereum/core"
    "github.com/ethereum/go-ethereum/core/types"
    "github.com/ethereum/go-ethereum/crypto"
    "github.com/ethereum/go-ethereum/eth"
    "github.com/ethereum/go-ethereum/eth/downloader"
    "github.com/ethereum/go-ethereum/eth/ethconfig"
    "github.com/ethereum/go-ethereum/node"
    "github.com/ethereum/go-ethereum/p2p"
    "github.com/ethereum/go-ethereum/params"
    "github.com/ethereum/go-ethereum/common"
)

const (
    port = 50051 // vsock port number for the gRPC server
)

func main() {
    // Create a vsock listener
    listener, err := vsock.Listen(uint32(port), &vsock.Config{})
    if err != nil {
        log.Fatalf("failed to listen: %v", err)
    }
    s := grpc.NewServer()
    
    // Start the Ethereum service
    n, ethInstance := startEthService()
    defer n.Close()
	
    // Create and register the BundleMergerServer
    bundleMergerServer := bundlemerger.NewBundleMergerServer(ethInstance)
    pb.RegisterBundleMergerServer(s, bundleMergerServer)

    log.Printf("Server listening on vsock port %d", port)
    if err := s.Serve(listener); err != nil {
        log.Fatalf("failed to serve: %v", err)
    }
}

func startEthService() (*node.Node, *eth.Ethereum) {
    // Generate the genesis block and a chain of blocks
    genesis, blocks := generateMergeChain(10, true)

    // Create a new node instance
    n, err := node.New(&node.Config{
        P2P: p2p.Config{
            ListenAddr:  "0.0.0.0:0",
            NoDiscovery: true,
            MaxPeers:    0,
        },
    })
    if err != nil {
        log.Fatal("can't create node:", err)
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
        log.Fatal("can't create eth service:", err)
    }

    if err := n.Start(); err != nil {
        log.Fatal("can't start node:", err)
    }

    if _, err := ethservice.BlockChain().InsertChain(blocks); err != nil {
        n.Close()
        log.Fatal("can't import test blocks:", err)
    }

    time.Sleep(500 * time.Millisecond) // Give txpool enough time to consume head event

    ethservice.SetEtherbase(testAddr)
    ethservice.SetSynced()

    return n, ethservice
}

func generateMergeChain(n int, merged bool) (*core.Genesis, []*types.Block) {
    config := *params.AllEthashProtocolChanges
    engine := beaconConsensus.New(ethash.NewFaker())

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
            types.NewTransaction(
                testNonce,
                common.HexToAddress("0x9a9070028361F7AAbeB3f2F2Dc07F82C4a98A02a"),
                big.NewInt(1),
                params.TxGas,
                big.NewInt(params.InitialBaseFee*2),
                nil,
            ),
            types.LatestSigner(&config),
            testKey,
        )
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
