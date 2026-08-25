package main

import (
	pb "decentis/ipc"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const SocketPath = "/tmp/decentis.sock"

func GetClient() (pb.DaemonControlClient, *grpc.ClientConn, error) {
	// 1. Use the native "unix:" scheme
	// 2. Inject WithAuthority("localhost") to satisfy Rust/Tonic's strict HTTP/2 parser
	conn, err := grpc.NewClient("unix:"+SocketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithAuthority("localhost"),
	)
	if err != nil {
		return nil, nil, err
	}

	client := pb.NewDaemonControlClient(conn)
	return client, conn, nil
}
