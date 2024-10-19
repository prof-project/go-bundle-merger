package main

import (
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/goccy/go-yaml"
	"github.com/prof-project/go-bundle-merger/bundlemerger"
	pb "github.com/prof-project/prof-grpc/go/profpb"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"log"
	"net"
	"os"
	"strconv"
)

const (
	port = 50051 // vsock port number for the gRPC server
)

type Config struct {
	ConsensusLayer struct {
		URL  string `yaml:"url" validate:"required,url"`
		Port int    `yaml:"port" validate:"required,min=1,max=65535"`
	} `yaml:"consensus-layer"`
	ExecutionLayer struct {
		URL  string `yaml:"url" validate:"required,url"`
		Port int    `yaml:"port" validate:"required,min=1,max=65535"`
	} `yaml:"execution-layer"`
}

func main() {
	config, err := loadConfig("config.yaml")
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	log.Printf("Consensus Layer URL: %s, Port: %d", config.ConsensusLayer.URL, config.ConsensusLayer.Port)
	log.Printf("Execution Layer URL: %s, Port: %d", config.ExecutionLayer.URL, config.ExecutionLayer.Port)

	// Create a vsock listener
	//listener, err := vsock.Listen(uint32(port), &vsock.Config{})
	listener, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()

	// Initialize the execution client
	ctx := context.Background()
	//execClient, err := rpc.DialContext(ctx, net.JoinHostPort(config.ExecutionLayer.URL, strconv.Itoa(config.ExecutionLayer.Port)))
	execClient, err := rpc.DialContext(ctx, config.ExecutionLayer.URL+":"+strconv.Itoa(config.ExecutionLayer.Port))
	if err != nil {
		log.Fatalf("Failed to connect to execution client: %v", err)
	}
	defer execClient.Close()

	ethClient := ethclient.NewClient(execClient)

	// use the ethClient
	number, err := ethClient.BlockNumber(ctx)
	if err != nil {
		log.Printf("Error querying block number: %v", err)
		return
	}
	log.Printf("Block number: %d", number)

	// access to rpc client
	/*var result string
	err = execClient.Call(ctx, "eth_blockNumber")
	if err != nil {
		log.Printf("Error querying execution client: %v", err)
	} else {
		log.Printf("Execution client block number: %s", result)
	}*/

	return

	// Create and register the BundleMergerServer
	bundleMergerServer := bundlemerger.NewBundleMergerServer(execClient)
	pb.RegisterBundleMergerServer(s, bundleMergerServer.UnimplementedBundleMergerServer)

	bundleServiceServer := bundlemerger.NewBundleServiceServer()
	pb.RegisterBundleServiceServer(s, bundleServiceServer)

	log.Printf("Server listening on vsock port %d", port)
	if err := s.Serve(listener); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}
