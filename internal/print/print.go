package print

import (
	"fmt"
	"strings"

	obom "github.com/Azure/obom/pkg"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

func PrintCreatorInfo(doc *v2_3.Document) {
	size := len(doc.CreationInfo.Creators)
	if size == 1 {
		creator := doc.CreationInfo.Creators[0]
		fmt.Printf("Creator:               %s\n", creator.Creator)
	} else if size > 1 {
		firstItem := doc.CreationInfo.Creators[0]
		fmt.Printf("Creators:              %s\n", firstItem.Creator)
		for _, creator := range doc.CreationInfo.Creators[1:] {
			fmt.Printf("                       %s\n", creator.Creator)
		}
	}
}

// PrintSBOMSummary returns the SPDX summary from the SBOM
func PrintSBOMSummary(sbomDoc *obom.SPDXDocument, desc *ocispec.Descriptor) {
	doc := sbomDoc.Document
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("Document Name:         %s\n", doc.DocumentName)
	fmt.Printf("Document Namespace:    %s\n", doc.DocumentNamespace)
	fmt.Printf("SPDX Version:          %s\n", sbomDoc.Version)
	if doc.CreationInfo != nil {
		fmt.Printf("Creation Date:         %s\n", doc.CreationInfo.Created)
		PrintCreatorInfo(doc)
	}
	if doc.Packages != nil {
		fmt.Printf("Packages:              %d\n", len(doc.Packages))
	}
	if doc.Files != nil {
		fmt.Printf("Files:                 %d\n", len(doc.Files))
	}
	fmt.Printf("Digest:                %s\n", desc.Digest)
	fmt.Println(strings.Repeat("=", 80))
}
