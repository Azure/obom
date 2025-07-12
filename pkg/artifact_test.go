package obom

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestLoadArtifactFromFile(t *testing.T) {
	// Define the path to the test file and its size
	filePath := "../examples/artifact.example.json"
	mediaType := "application/json"
	size := int64(84)

	// Call the function with the test file path and media type
	desc, _, err := LoadArtifactFromFile(filePath, mediaType)

	// Check that there was no error
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Check that the returned desc has the expected values
	if desc.MediaType != mediaType {
		t.Errorf("expected desc.MediaType to be '%s', got: %s", mediaType, desc.MediaType)
	}
	if desc.Size != size {
		t.Errorf("expected desc.Size to be %d, got: %d", size, desc.Size)
	}
	if desc.Digest.String() != "sha256:2dacf1160f3fde8ce048bc00da86909f46c65cfe753aed83a04b3df48fb8ddc4" {
		t.Errorf("expected desc.Digest to be 'sha256:2dacf1160f3fde8ce048bc00da86909f46c65cfe753aed83a04b3df48fb8ddc4', got: %s", desc.Digest.String())
	}
}

func TestLoadArtifactFromReader(t *testing.T) {
	// Define the test data and its size
	testData := []byte(`{"test": "data"}`)
	mediaType := "application/json"
	size := int64(len(testData))

	// Create a test reader with the test data
	reader := io.NopCloser(bytes.NewReader(testData))

	// Call the function with the test reader and media type
	desc, _, err := LoadArtifactFromReader(reader, mediaType)

	// Check that there was no error
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Check that the returned desc has the expected values
	if desc.MediaType != mediaType {
		t.Errorf("expected desc.MediaType to be '%s', got: %s", mediaType, desc.MediaType)
	}
	if desc.Size != size {
		t.Errorf("expected desc.Size to be %d, got: %d", size, desc.Size)
	}
	if desc.Digest.String() != "sha256:40b61fe1b15af0a4d5402735b26343e8cf8a045f4d81710e6108a21d91eaf366" {
		t.Errorf("expected desc.Digest to be 'sha256:40b61fe1b15af0a4d5402735b26343e8cf8a045f4d81710e6108a21d91eaf366', got: %s", desc.Digest.String())
	}
}

func TestLoadArtifactFromReader_WithFilename(t *testing.T) {
	// Define the test data and its size
	testData := []byte(`{"test": "data"}`)
	mediaType := "application/json"
	artifactFilename := "test-artifact.json"

	// Create a test reader with the test data
	reader := io.NopCloser(bytes.NewReader(testData))

	// Call the function with the test reader, media type, and filename
	desc, _, err := LoadArtifactFromReader(reader, mediaType, artifactFilename)

	// Check that there was no error
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Check that the artifact filename annotation is set
	if desc.Annotations == nil {
		t.Fatalf("expected annotations to be set, got nil")
	}

	title, exists := desc.Annotations[ocispec.AnnotationTitle]
	if !exists {
		t.Errorf("expected annotation %s to exist", ocispec.AnnotationTitle)
	}
	if title != artifactFilename {
		t.Errorf("expected annotation %s to be '%s', got: %s", ocispec.AnnotationTitle, artifactFilename, title)
	}
}

func TestLoadArtifactFromReader_WithoutFilename(t *testing.T) {
	// Define the test data and its size
	testData := []byte(`{"test": "data"}`)
	mediaType := "application/json"

	// Create a test reader with the test data
	reader := io.NopCloser(bytes.NewReader(testData))

	// Call the function with the test reader and media type, but no filename
	desc, _, err := LoadArtifactFromReader(reader, mediaType)

	// Check that there was no error
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Check that no annotations are set when filename is empty
	if desc.Annotations != nil {
		if _, exists := desc.Annotations[ocispec.AnnotationTitle]; exists {
			t.Errorf("expected no %s annotation when filename is empty, but it was set", ocispec.AnnotationTitle)
		}
	}
}

func TestLoadArtifactFromReader_BackwardCompatibility(t *testing.T) {
	// Test that calling without the filename parameter still works (backward compatibility)
	testData := []byte(`{"test": "data"}`)
	mediaType := "application/json"

	// Create a test reader with the test data
	reader := io.NopCloser(bytes.NewReader(testData))

	// Call the function with just the required parameters (old way)
	desc, _, err := LoadArtifactFromReader(reader, mediaType)

	// Check that there was no error
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Check that no annotations are set when filename is not provided
	if desc.Annotations != nil {
		if _, exists := desc.Annotations[ocispec.AnnotationTitle]; exists {
			t.Errorf("expected no %s annotation when filename is not provided, but it was set", ocispec.AnnotationTitle)
		}
	}
}

func TestLoadSBOMFromReader_BackwardCompatibility(t *testing.T) {
	// Test that calling without the filename parameter still works (backward compatibility)
	spdxStr := `{
		"SPDXID": "SPDXRef-DOCUMENT",
		"spdxVersion": "SPDX-2.2",
		"name" : "SPDX-Example",
		"documentNamespace" : "SPDX-Namespace-Example",
		"creationInfo": {
			"created": "2020-07-23T18:30:22Z",
			"creators": ["Tool: SPDX-Java-Tools-v2.1.20"]
		}
	}`

	// Create a test reader with the SPDX JSON data
	reader := io.NopCloser(strings.NewReader(spdxStr))

	// Call the function with just the required parameters (old way)
	sbomDoc, desc, _, err := LoadSBOMFromReader(reader, true)

	// Check that there was no error
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Check that the SBOM document was loaded correctly
	if sbomDoc.Version != "SPDX-2.2" {
		t.Errorf("expected SPDXVersion to be 'SPDX-2.2', got: %v", sbomDoc.Version)
	}

	// Check that no filename annotation is set when filename is not provided
	if desc.Annotations != nil {
		if _, exists := desc.Annotations[ocispec.AnnotationTitle]; exists {
			t.Errorf("expected no %s annotation when filename is not provided, but it was set", ocispec.AnnotationTitle)
		}
	}
}

func TestLoadSBOMFromReader_WithOptionalFilename(t *testing.T) {
	// Test that calling with the optional filename parameter works
	spdxStr := `{
		"SPDXID": "SPDXRef-DOCUMENT",
		"spdxVersion": "SPDX-2.2",
		"name" : "SPDX-Example",
		"documentNamespace" : "SPDX-Namespace-Example",
		"creationInfo": {
			"created": "2020-07-23T18:30:22Z",
			"creators": ["Tool: SPDX-Java-Tools-v2.1.20"]
		}
	}`

	// Create a test reader with the SPDX JSON data
	reader := io.NopCloser(strings.NewReader(spdxStr))
	artifactFilename := "test-sbom.spdx.json"

	// Call the function with the optional filename parameter
	sbomDoc, desc, _, err := LoadSBOMFromReader(reader, true, artifactFilename)

	// Check that there was no error
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Check that the SBOM document was loaded correctly
	if sbomDoc.Version != "SPDX-2.2" {
		t.Errorf("expected SPDXVersion to be 'SPDX-2.2', got: %v", sbomDoc.Version)
	}

	// Check that the artifact filename annotation is set
	if desc.Annotations == nil {
		t.Fatalf("expected annotations to be set, got nil")
	}

	title, exists := desc.Annotations[ocispec.AnnotationTitle]
	if !exists {
		t.Errorf("expected annotation %s to exist", ocispec.AnnotationTitle)
	}
	if title != artifactFilename {
		t.Errorf("expected annotation %s to be '%s', got: %s", ocispec.AnnotationTitle, artifactFilename, title)
	}
}

func TestLoadArtifactFromFile_ArtifactFilenameAnnotation(t *testing.T) {
	// Define the path to the test file
	filePath := "../examples/artifact.example.json"
	mediaType := "application/json"
	expectedFilename := "artifact.example.json" // Only the base filename, not the full path

	// Call the function with the test file path and media type
	desc, _, err := LoadArtifactFromFile(filePath, mediaType)

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

func TestLoadArtifactFromFile_FilenameExtractionFromPath(t *testing.T) {
	// Test that filename is correctly extracted from various path formats
	testCases := []struct {
		name         string
		filePath     string
		expectedName string
	}{
		{
			name:         "relative path with slash",
			filePath:     "../examples/artifact.example.json",
			expectedName: "artifact.example.json",
		},
		{
			name:         "simple filename",
			filePath:     "artifact.example.json",
			expectedName: "artifact.example.json",
		},
	}

	mediaType := "application/json"

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Skip if file doesn't exist (we're testing the filename extraction logic)
			if _, err := os.Stat(tc.filePath); os.IsNotExist(err) {
				t.Skipf("Test file %s does not exist", tc.filePath)
			}

			desc, _, err := LoadArtifactFromFile(tc.filePath, mediaType)

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
