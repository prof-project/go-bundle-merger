package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/ethereum/go-ethereum/rpc"
	"github.com/goccy/go-yaml"
	"github.com/prof-project/go-bundle-merger/bundlemerger"
	pb "github.com/prof-project/prof-grpc/go/profpb"
	relay_grpc "github.com/prof-project/prof-grpc/go/relay_grpc"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

const (
	port = 50051 // vsock port number for the gRPC server
)

type ExecutionLayerConfig struct {
	URL  string `yaml:"url"`
	Port int    `yaml:"port"`
}

type Config struct {
	ConsensusLayer struct {
		URL  string `yaml:"url"`
		Port int    `yaml:"port"`
	} `yaml:"consensus-layer"`
	ExecutionLayer struct {
		Development ExecutionLayerConfig `yaml:"development"`
		Kurtosis    ExecutionLayerConfig `yaml:"kurtosis"`
		Production  ExecutionLayerConfig `yaml:"production"`
	} `yaml:"execution-layer"`
	Environment string `yaml:"environment"`
}

func main() {
	config, err := loadConfig("config.yaml")
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	// Create a vsock listener
	// listener, err := vsock.Listen(uint32(port), &vsock.Config{})
	listener, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()

	// Initialize the execution client
	ctx := context.Background()
	execConfig := getExecutionLayerConfig(config)
	execURL := fmt.Sprintf("%s:%d", execConfig.URL, execConfig.Port)
	log.Printf("Execution Layer URL: %s", execURL)
	execClient, err := rpc.DialContext(ctx, execURL)
	if err != nil {
		log.Fatalf("Failed to connect to execution client: %v", err)
	}
	defer execClient.Close()

	bundleServiceServer := bundlemerger.NewBundleServiceServer()
	pb.RegisterBundleServiceServer(s, bundleServiceServer)

	// Create and register the BundleMergerServer
	opts := bundlemerger.BundleMergerServerOpts{
		ExecClient:    execClient,
		BundleService: bundleServiceServer,
	}

	bundleMergerServer := bundlemerger.NewBundleMergerServerEth(opts)
	relay_grpc.RegisterEnricherServer(s, bundleMergerServer.UnimplementedEnricherServer)

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

	// Replace environment variables in the YAML
	expandedData := os.ExpandEnv(string(data))

	var config Config
	err = yaml.Unmarshal([]byte(expandedData), &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func getExecutionLayerConfig(config *Config) ExecutionLayerConfig {
	switch config.Environment {
	case "production":
		return config.ExecutionLayer.Production
	case "kurtosis":
		return config.ExecutionLayer.Kurtosis
	default: // development
		return config.ExecutionLayer.Development
	}
}
