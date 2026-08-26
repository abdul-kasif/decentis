package main

import (
	"context"
	"fmt"
	"io"
	"path/filepath" // <-- Add this import

	pb "decentis/ipc"

	"github.com/spf13/cobra"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

var sendCmd = &cobra.Command{
	Use:   "send [file_path] [peer_vip]",
	Short: "Send a file to a remote peer over the Decentis mesh",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]
		peerVip := args[1]

		absPath, err := filepath.Abs(filePath)
		if err != nil {
			return fmt.Errorf("invalid file path: %w", err)
		}
		// -----------------------------------------

		client, conn, err := GetClient()
		if err != nil {
			return fmt.Errorf("failed to connect to daemon: %w", err)
		}
		defer conn.Close()

		req := &pb.SendFileRequest{
			FilePath:      absPath, // <-- Send the absolute path to Rust
			PeerVirtualIp: peerVip,
		}

		stream, err := client.InitiateSend(context.Background(), req)
		if err != nil {
			return fmt.Errorf("rpc error: %w", err)
		}

		p := mpb.New(mpb.WithWidth(60))
		var bar *mpb.Bar

		for {
			progress, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("transfer error: %w", err)
			}

			if bar == nil {
				bar = p.AddBar(int64(progress.TotalBytes),
					mpb.PrependDecorators(
						decor.Name(filepath.Base(absPath)+" "), // Just show the filename in the UI
						decor.CountersKibiByte("% .2f / % .2f"),
					),
					mpb.AppendDecorators(
						decor.EwmaSpeed(decor.SizeB1024(0), "% .2f", 60),
						decor.Percentage(decor.WCSyncSpace),
					),
				)
			}

			bar.SetCurrent(int64(progress.BytesTransferred))

			if progress.Status == "COMPLETED" {
				bar.SetTotal(int64(progress.TotalBytes), true)
				break
			}
		}

		p.Wait()
		fmt.Println("\n✅ Transfer Complete!")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(sendCmd)
}
