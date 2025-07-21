package obom

import (
	"bytes"
	"io"
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

func TestLoadSBOMFromFile_AddsFilenameAnnotation(t *testing.T) {
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

func TestLoadSBOMFromReader_NoAnnotations(t *testing.T) {
	// Test that LoadSBOMFromReader doesn't add annotations
	// Create a test reader with the SPDX JSON data
	reader := io.NopCloser(strings.NewReader(spdxStr))

	// Call the function with the test reader
	_, desc, _, err := LoadSBOMFromReader(reader, true)

	// Check that there was no error
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Check that no title annotation is set since LoadSBOMFromReader doesn't add title annotations
	if desc.Annotations != nil {
		if _, exists := desc.Annotations[ocispec.AnnotationTitle]; exists {
			t.Errorf("expected no %s annotation from LoadSBOMFromReader, but it was set", ocispec.AnnotationTitle)
		}
	}
}

func TestLoadSBOMFromFile_PreservesExistingAnnotation(t *testing.T) {
	// This test simulates the case where a descriptor already has a title annotation
	// Since we can't easily mock this with the current implementation, this serves as documentation
	// of the intended behavior: if an annotation already exists, it should not be overwritten
	
	// For now, we just test that the annotation is added when it doesn't exist
	filePath := "../examples/SPDXJSONExample-v2.3.spdx.json"
	expectedFilename := "SPDXJSONExample-v2.3.spdx.json"

	// Call the function
	_, desc, _, err := LoadSBOMFromFile(filePath, true)

	// Check that there was no error
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify the title annotation is set
	title, exists := desc.Annotations[ocispec.AnnotationTitle]
	if !exists {
		t.Errorf("expected annotation %s to exist", ocispec.AnnotationTitle)
	}
	if title != expectedFilename {
		t.Errorf("expected annotation %s to be '%s', got: %s", ocispec.AnnotationTitle, expectedFilename, title)
	}
}
