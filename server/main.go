package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"

	pb "decentis/server/signaling"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type NodeSession struct {
	ID         string
	PublicIP   string
	PublicPort uint32
	LocalIP    string
	EventChan  chan *pb.SignalMessage
}

type SignalingServer struct {
	pb.UnimplementedSignalingServiceServer
	mu    sync.RWMutex
	nodes map[string]*NodeSession
}

func NewSignalingServer() *SignalingServer {
	return &SignalingServer{
		nodes: make(map[string]*NodeSession),
	}
}

func (s *SignalingServer) StartConnection(req *pb.SignalMessage, stream pb.SignalingService_StartConnectionServer) error {
	registerPayload := req.GetRegister()
	if registerPayload == nil {
		return fmt.Errorf("initial message must be a RegisterNode payload")
	}

	nodeID := registerPayload.NodeId
	eventChan := make(chan *pb.SignalMessage, 32)

	session := &NodeSession{
		ID:         nodeID,
		PublicIP:   registerPayload.PublicIp,
		PublicPort: registerPayload.PublicPort,
		LocalIP:    registerPayload.LocalIp,
		EventChan:  eventChan,
	}

	s.mu.Lock()
	s.nodes[nodeID] = session
	s.mu.Unlock()

	log.Printf("[+] Node Registered: %s at %s:%d (LAN: %s)", nodeID, session.PublicIP, session.PublicPort, session.LocalIP)

	// Explicitly flush HTTP/2 headers to unblock the Rust gRPC client
	if err := stream.SendHeader(nil); err != nil {
		log.Printf("Warning: failed to send headers: %v", err)
	}

	defer func() {
		s.mu.Lock()
		delete(s.nodes, nodeID)
		s.mu.Unlock()
		close(eventChan)
		log.Printf("[-] Node Disconnected: %s", nodeID)
	}()

	// Push events down to the node as they arrive
	for msg := range eventChan {
		if err := stream.Send(msg); err != nil {
			return err
		}
	}

	return nil
}

func (s *SignalingServer) SendSignal(ctx context.Context, req *pb.SignalMessage) (*pb.SignalResponse, error) {
	dialPayload := req.GetDial()
	if dialPayload == nil {
		return &pb.SignalResponse{Success: false, Message: "Unsupported payload"}, nil
	}

	s.mu.RLock()
	targetNode, targetExists := s.nodes[dialPayload.TargetNodeId]
	myNode, myExists := s.nodes[dialPayload.MyNodeId]
	s.mu.RUnlock()

	if !targetExists || !myExists {
		return &pb.SignalResponse{Success: false, Message: "Target peer or source node not found"}, nil
	}

	log.Printf("[⇄] Mutual rendezvous: %s <-> %s", dialPayload.MyNodeId, dialPayload.TargetNodeId)

	// Send target details to initiator
	myNode.EventChan <- &pb.SignalMessage{
		Payload: &pb.SignalMessage_PeerFound{
			PeerFound: &pb.PeerFound{
				TargetNodeId: targetNode.ID,
				PublicIp:     targetNode.PublicIP,
				PublicPort:   targetNode.PublicPort,
				LocalIp:      targetNode.LocalIP,
			},
		},
	}

	// Send initiator details to target (triggers simultaneous hole punching)
	targetNode.EventChan <- &pb.SignalMessage{
		Payload: &pb.SignalMessage_PeerFound{
			PeerFound: &pb.PeerFound{
				TargetNodeId: myNode.ID,
				PublicIp:     myNode.PublicIP,
				PublicPort:   myNode.PublicPort,
				LocalIp:      myNode.LocalIP,
			},
		},
	}

	return &pb.SignalResponse{Success: true, Message: "Peer rendezvous initiated"}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen on :50051: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterSignalingServiceServer(grpcServer, NewSignalingServer())
	reflection.Register(grpcServer)

	log.Printf("Decentis Micro-Signaling Server running on :50051")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("server failure: %v", err)
	}
}
