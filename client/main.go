package main

import (
	"context"
	"fmt"
	"os"
	"time"

	pb "decentis/ipc"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "decentis",
	Short: "Decentis P2P Mesh VPN & File Relay CLI",
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Query the status of the local Decentis daemon",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, conn, err := GetClient()
		if err != nil {
			return fmt.Errorf("failed to connect to daemon: %w", err)
		}
		defer conn.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		resp, err := client.GetStatus(ctx, &pb.StatusRequest{})
		if err != nil {
			return fmt.Errorf("daemon error: %w", err)
		}

		fmt.Println("--- Decentis Daemon Status ---")
		fmt.Printf("Virtual IP   : %s\n", resp.VirtualIp)
		fmt.Printf("Active       : %t\n", resp.IsActive)
		fmt.Printf("Active Peers : %d\n", resp.ActivePeers)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
