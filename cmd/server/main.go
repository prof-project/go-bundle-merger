package main

import (
	"flag"
	"log"
	"net"

	"github.com/ethereum/go-ethereum/rpc"
	"github.com/prof-project/go-bundle-merger/bundlemerger"
	pb "github.com/prof-project/prof-grpc/go/profpb"
	relay_grpc "github.com/bloXroute-Labs/relay-grpc"
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

	listener, err := net.Listen("tcp", ":50051")
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

	bundleMergerServer := bundlemerger.NewBundleMergerServerEth(opts)
	relay_grpc.RegisterEnricherServer(s, bundleMergerServer)

	log.Printf("Server listening on port %d", port)
	if err := s.Serve(listener); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
