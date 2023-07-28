package obom

import (
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
	size := int64(len([]byte(spdx)))

	// Create a test reader with the SPDX JSON data
	reader := io.NopCloser(strings.NewReader(spdx))

	// Call the function with the test reader
	doc, desc, err := LoadSBOMFromReader(reader, size)

	// Check that there was no error
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Check that the returned doc and desc have the expected values
	// You'll need to replace these checks with checks that are appropriate for your code
	if doc.DocumentName != "SPDX-Example" {
		t.Errorf("expected document name to be 'SPDX-Example', got: %v", doc.DocumentName)
	}
	if desc.Size != size {
		t.Errorf("expected desc.Size to be %v, got: %v", size, desc.Size)
	}
}

func TestLoadSBOMFromFile(t *testing.T) {
	// Define the path to the test file and its size
	filePath := "../examples/SPDXJSONExample-v2.3.spdx.json"
	size := int64(21342)

	// Call the function with the test file path
	doc, desc, err := LoadSBOMFromFile(filePath)

	// Check that there was no error
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Check that the returned doc and desc have the expected values
	// You'll need to replace these checks with checks that are appropriate for your code
	if doc.DocumentName != "SPDX-Tools-v2.0" {
		t.Errorf("expected document name to be 'SPDX-Tools-v2.0', got: %v", doc.DocumentName)
	}
	if desc.Size != size {
		t.Errorf("expected desc.Size to be %v, got: %v", size, desc.Size)
	}
}
