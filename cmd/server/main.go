package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	relay_grpc "github.com/bloXroute-Labs/relay-grpc"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/joho/godotenv"
	"github.com/prof-project/go-bundle-merger/bundlemerger"
	pb "github.com/prof-project/prof-grpc/go/profpb"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

const (
	port = 50051
)

func main() {

	// Load .env file from project root
	if err := godotenv.Load("../../.env"); err != nil {
		log.Printf("Warning: .env file not found: %v", err)
	}

	builderURI := flag.String("builder-uri", "", "URI for the execution layer/builder")
	flag.Parse()

	if *builderURI == "" {
		log.Fatal("--builder-uri flag is required")
	}

	// Read wallet configuration from environment
	walletPrivKey := os.Getenv("WALLET_PRIVATE_KEY")
	if walletPrivKey == "" {
		log.Fatal("WALLET_PRIVATE_KEY environment variable is required")
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()

	ctx := context.Background()
	execClient, err := rpc.DialContext(ctx, *builderURI)
	if err != nil {
		log.Fatalf("Failed to connect to execution client: %v", err)
	}
	defer execClient.Close()

	bundleServiceServer := bundlemerger.NewBundleServiceServer()
	pb.RegisterBundleServiceServer(s, bundleServiceServer)

	opts := bundlemerger.BundleMergerServerOpts{
		ExecClient:    execClient,
		BundleService: bundleServiceServer,
		WalletPrivKey: walletPrivKey,
	}

	// Start health check endpoint
	go startHealthCheck()

	bundleMergerServer := bundlemerger.NewBundleMergerServerEth(opts)
	if bundleMergerServer == nil {
		log.Fatal("Failed to initialize bundle merger server")
	}
	relay_grpc.RegisterEnricherServer(s, bundleMergerServer)

	log.Printf("Server listening on port %d", port)
	if err := s.Serve(listener); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

// Start a simple HTTP server for health checks
func startHealthCheck() {
	http.HandleFunc("/enhancer/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{\"status\": \"healthy\"}"))
	})
	log.Println("Health check endpoint running on port 80...")
	if err := http.ListenAndServe(":80", nil); err != nil {
		log.Fatalf("Failed to start health check endpoint: %v", err)
	}
}
