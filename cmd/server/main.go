package main

import (
	"log"

	"github.com/mdlayher/vsock"
	"google.golang.org/grpc"

	"github.com/prof-project/go-bundle-merger/bundlemerger"
	pb "github.com/prof-project/prof-grpc/go/profpb"
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

	// Create and register the BundleMergerServer
	bundleMergerServer := bundlemerger.NewBundleMergerServer()
	pb.RegisterBundleMergerServer(s, bundleMergerServer.UnimplementedBundleMergerServer)

	bundleServiceServer := bundlemerger.NewBundleServiceServer()
	pb.RegisterBundleServiceServer(s, bundleServiceServer)

	log.Printf("Server listening on vsock port %d", port)
	if err := s.Serve(listener); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
