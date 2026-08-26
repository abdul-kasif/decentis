package main

import (
	"fmt"
	"os"

	pb "decentis/ipc"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func GetClient() (pb.DaemonControlClient, *grpc.ClientConn, error) {
	// Read PORT from environment, default to 51820
	port := os.Getenv("PORT")
	if port == "" {
		port = "51820"
	}

	socketPath := fmt.Sprintf("/tmp/decentis_%s.sock", port)

	conn, err := grpc.NewClient("unix:"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithAuthority("localhost"),
	)
	if err != nil {
		return nil, nil, err
	}

	client := pb.NewDaemonControlClient(conn)
	return client, conn, nil
}
