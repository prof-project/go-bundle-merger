package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/ethereum/go-ethereum/rpc"
	"github.com/prof-project/go-bundle-merger/bundlemerger"
	pb "github.com/prof-project/prof-grpc/go/profpb"
	relay_grpc "github.com/prof-project/prof-grpc/go/relay_grpc"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

const (
	port = 50051
)

func main() {
	builderURI := flag.String("builder-uri", "", "URI for the execution layer/builder")
	flag.Parse()

	if *builderURI == "" {
		log.Fatal("--builder-uri flag is required")
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
	}

	// Start health check endpoint
	go startHealthCheck()

	bundleMergerServer := bundlemerger.NewBundleMergerServerEth(opts)
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
