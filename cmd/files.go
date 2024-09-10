package cmd

import (
	"fmt"
	"os"

	obom "github.com/Azure/obom/pkg"
	"github.com/spf13/cobra"
)

type filesOptions struct {
	filename string
}

func filesCmd() *cobra.Command {
	var opts filesOptions
	var filesCmd = &cobra.Command{
		Use:   "files",
		Short: "List files the SBOM",
		Long: `List files the SBOM

Example:
	obom files -f ./examples/SPDXJSONExample-v2.3.spdx.json`,
		Run: func(cmd *cobra.Command, args []string) {
			sbom, _, _, err := obom.LoadSBOMFromFile(opts.filename, true)
			if err != nil {
				fmt.Println("Error loading SBOM:", err)
				os.Exit(1)
			}

			files, err := obom.GetFiles(sbom.Document)
			if err != nil {
				fmt.Println("Error getting files:", err)
				os.Exit(1)
			}

			for _, pkg := range files {
				fmt.Println(pkg)
			}
		},
	}

	filesCmd.Flags().StringVarP(&opts.filename, "file", "f", "", "Path to the SPDX SBOM file")
	filesCmd.MarkFlagRequired("file")

	return filesCmd
}
