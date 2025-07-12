package obom

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const spdxStr string = `{
			"SPDXID": "SPDXRef-DOCUMENT",
			"spdxVersion": "SPDX-2.2",
			"name" : "SPDX-Example",
			"documentNamespace" : "SPDX-Namespace-Example",
			"creationInfo": {
					"created": "2020-07-23T18:30:22Z",
					"creators": ["Tool: SPDX-Java-Tools-v2.1.20", "Organization: Source Auditor Inc."],
					"licenseListVersion": "3.6"
			}
	}`

const nonCompliantSPDXStr string = `{
			"SPDXID": "NonCompliant",
			"spdxVersion": "SPDX-2.2",
			"name" : "SPDX-Example",
			"documentNamespace" : "SPDX-Namespace-Example",
			"creationInfo": {
					"created": "2020-07-23T18:30:22Z",
					"creators": ["Tool: SPDX-Java-Tools-v2.1.20", "Organization: Source Auditor Inc."],
					"licenseListVersion": "3.6"
			}
	}`

func TestLoadSBOMFromReader(t *testing.T) {

	// Calculate the size of the SPDX string in bytes
	expectedBytes := []byte(spdxStr)
	size := int64(len(expectedBytes))

	// Create a test reader with the SPDX JSON data
	reader := io.NopCloser(strings.NewReader(spdxStr))

	// Call the function with the test reader
	sbomDoc, desc, sbomBytes, err := LoadSBOMFromReader(reader, true)

	// Check that there was no error
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if sbomDoc.Version != "SPDX-2.2" {
		t.Errorf("expected SPDXVersion to be 'SPDX-2.2', got: %v", sbomDoc.Version)
	}

	doc := sbomDoc.Document
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

func TestLoadSBOMFromReader_NonCompliantSucceedsWhenStrictFalse(t *testing.T) {
	// Create a test reader with the SPDX JSON data
	reader := io.NopCloser(strings.NewReader(nonCompliantSPDXStr))

	// Call the function with the test reader
	sbomDoc, _, _, err := LoadSBOMFromReader(reader, false)

	// Check that there was no error
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if sbomDoc.Version != "SPDX-2.2" {
		t.Errorf("expected SPDXVersion to be 'SPDX-2.2', got: %v", sbomDoc.Version)
	}
}

func TestLoadSBOMFromReader_NonCompliantFailsWhenStrictTrue(t *testing.T) {
	// Create a test reader with the SPDX JSON data
	reader := io.NopCloser(strings.NewReader(nonCompliantSPDXStr))

	// Call the function with the test reader
	_, _, _, err := LoadSBOMFromReader(reader, true)

	// Check that there was no error
	if err == nil {
		t.Fatalf("expected error when parsing with strict, got no err")
	}
}

func TestLoadSBOMFromFile(t *testing.T) {
	// Define the path to the test file and its size
	filePath := "../examples/SPDXJSONExample-v2.3.spdx.json"
	size := int64(21342)

	// Call the function with the test file path
	sbomDoc, desc, _, err := LoadSBOMFromFile(filePath, true)

	// Check that there was no error
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if sbomDoc.Version != "SPDX-2.3" {
		t.Errorf("expected SPDXVersion to be 'SPDX-2.3', got: %v", sbomDoc.Version)
	}

	doc := sbomDoc.Document
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

func TestLoadSBOMFromFile_ArtifactFilenameAnnotation(t *testing.T) {
	// Define the path to the test file
	filePath := "../examples/SPDXJSONExample-v2.3.spdx.json"
	expectedFilename := "SPDXJSONExample-v2.3.spdx.json" // Only the base filename, not the full path

	// Call the function with the test file path
	_, desc, _, err := LoadSBOMFromFile(filePath, true)

	// Check that there was no error
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Check that the artifact filename annotation is set with just the filename
	if desc.Annotations == nil {
		t.Fatalf("expected annotations to be set, got nil")
	}

	title, exists := desc.Annotations[ocispec.AnnotationTitle]
	if !exists {
		t.Errorf("expected annotation %s to exist", ocispec.AnnotationTitle)
	}
	if title != expectedFilename {
		t.Errorf("expected annotation %s to be '%s', got: %s", ocispec.AnnotationTitle, expectedFilename, title)
	}
}

func TestLoadSBOMFromFile_FilenameExtractionFromPath(t *testing.T) {
	// Test that filename is correctly extracted from various path formats
	testCases := []struct {
		name         string
		filePath     string
		expectedName string
	}{
		{
			name:         "relative path with slash",
			filePath:     "../examples/SPDXJSONExample-v2.3.spdx.json",
			expectedName: "SPDXJSONExample-v2.3.spdx.json",
		},
		{
			name:         "simple filename",
			filePath:     "SPDXJSONExample-v2.3.spdx.json",
			expectedName: "SPDXJSONExample-v2.3.spdx.json",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Skip if file doesn't exist (we're testing the filename extraction logic)
			if _, err := os.Stat(tc.filePath); os.IsNotExist(err) {
				t.Skipf("Test file %s does not exist", tc.filePath)
			}

			_, desc, _, err := LoadSBOMFromFile(tc.filePath, true)

			// Check that there was no error
			if err != nil {
				t.Fatalf("expected no error for path '%s', got: %v", tc.filePath, err)
			}

			// Check that only the filename (not the path) is in the annotation
			if desc.Annotations == nil {
				t.Fatalf("expected annotations to be set for path '%s', got nil", tc.filePath)
			}

			title, exists := desc.Annotations[ocispec.AnnotationTitle]
			if !exists {
				t.Errorf("expected annotation %s to exist for path '%s'", ocispec.AnnotationTitle, tc.filePath)
			}
			if title != tc.expectedName {
				t.Errorf("for path '%s', expected annotation %s to be '%s', got: %s", tc.filePath, ocispec.AnnotationTitle, tc.expectedName, title)
			}
		})
	}
}

func TestGetAnnotations(t *testing.T) {
	// Create a test reader with the SPDX JSON data
	reader := io.NopCloser(strings.NewReader(spdxStr))

	// Call the function with the test reader
	sbomDoc, _, _, err := LoadSBOMFromReader(reader, true)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Call the function with the SPDX document
	annotations, err := GetAnnotations(sbomDoc)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Check that the returned annotations have the expected values
	if len(annotations) != 5 {
		t.Errorf("expected 5 annotations, got: %v", len(annotations))
	}

	if annotations[OCI_ANNOTATION_DOCUMENT_NAME] != "SPDX-Example" {
		t.Errorf("expected document name annotation to be 'SPDX-Example', got: %v", annotations[OCI_ANNOTATION_DOCUMENT_NAME])
	}

	if annotations[OCI_ANNOTATION_DOCUMENT_NAMESPACE] != "SPDX-Namespace-Example" {
		t.Errorf("expected document name annotation to be 'SPDX-Example', got: %v", annotations[OCI_ANNOTATION_DOCUMENT_NAME])
	}

	if annotations[OCI_ANNOTATION_SPDX_VERSION] != "SPDX-2.2" {
		t.Errorf("expected SPDX version annotation to be 'SPDX-2.2', got: %v", annotations[OCI_ANNOTATION_SPDX_VERSION])
	}

	if annotations[OCI_ANNOTATION_CREATION_DATE] != "2020-07-23T18:30:22Z" {
		t.Errorf("expected creation date annotation to be '2020-07-23T18:30:22Z', got: %v", annotations[OCI_ANNOTATION_CREATION_DATE])
	}

	if annotations[OCI_ANNOTATION_CREATORS] != "Tool: SPDX-Java-Tools-v2.1.20, Organization: Source Auditor Inc." {
		t.Errorf("expected creators annotation to be 'Tool: SPDX-Java-Tools-v2.1.20, Organization: Source Auditor Inc.', got: %v", annotations[OCI_ANNOTATION_CREATORS])
	}
}
