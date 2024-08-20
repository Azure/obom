package obom

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestLoadSBOMFromReader(t *testing.T) {
	// Create a test SPDX JSON string
	spdx := `{
			"SPDXID": "SPDXRef-DOCUMENT",
			"spdxVersion": "SPDX-2.3",
			"name" : "SPDX-Example",
			"creationInfo": {
					"created": "2020-07-23T18:30:22Z",
					"creators": ["Tool: SPDX-Java-Tools-v2.1.20", "Organization: Source Auditor Inc."],
					"licenseListVersion": "3.6"
			}
	}`

	// Calculate the size of the SPDX string in bytes
	expectedBytes := []byte(spdx)
	size := int64(len(expectedBytes))

	// Create a test reader with the SPDX JSON data
	reader := io.NopCloser(strings.NewReader(spdx))

	// Call the function with the test reader
	doc, desc, sbomBytes, err := LoadSBOMFromReader(reader, size)

	// Check that there was no error
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Check that the returned doc and desc have the expected values
	if doc.DocumentName != "SPDX-Example" {
		t.Errorf("expected document name to be 'SPDX-Example', got: %v", doc.DocumentName)
	}
	if desc.Size != size {
		t.Errorf("expected desc.Size to be %v, got: %v", size, desc.Size)
	}
	// Check if the byte arrays are equal
	if !bytes.Equal(sbomBytes, expectedBytes) {
		t.Errorf("expected sbomBytes to be %v, got: %v", expectedBytes, sbomBytes)
	}
}

func TestLoadSBOMFromFile(t *testing.T) {
	// Define the path to the test file and its size
	filePath := "../examples/SPDXJSONExample-v2.3.spdx.json"
	size := int64(21342)

	// Call the function with the test file path
	doc, desc, _, err := LoadSBOMFromFile(filePath)

	// Check that there was no error
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Check that the returned doc and desc have the expected values
	if doc.DocumentName != "SPDX-Tools-v2.0" {
		t.Errorf("expected document name to be 'SPDX-Tools-v2.0', got: %v", doc.DocumentName)
	}
	if desc.Size != size {
		t.Errorf("expected desc.Size to be %v, got: %v", size, desc.Size)
	}
	if desc.Digest.String() != "sha256:2de3741a7be1be5f5e54e837524f2ec627fedfb82307dc004ae03b195abc092f" {
		t.Errorf("expected desc.Digest to be 'sha256:2de3741a7be1be5f5e54e837524f2ec627fedfb82307dc004ae03b195abc092f', got: %v", desc.Digest.String())
	}
}
