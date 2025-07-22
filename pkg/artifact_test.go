package obom

import (
	"bytes"
	"io"
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

func TestLoadArtifactFromFile_AddsFilenameAnnotation(t *testing.T) {
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

func TestLoadArtifactFromReader_NoAnnotations(t *testing.T) {
	// Test that LoadArtifactFromReader doesn't add annotations
	testData := []byte(`{"test": "data"}`)
	mediaType := "application/json"

	// Create a test reader with the test data
	reader := io.NopCloser(bytes.NewReader(testData))

	// Call the function with the test reader and media type
	desc, _, err := LoadArtifactFromReader(reader, mediaType)

	// Check that there was no error
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Check that no annotations are set since LoadArtifactFromReader doesn't add title annotations
	if desc.Annotations != nil {
		if _, exists := desc.Annotations[ocispec.AnnotationTitle]; exists {
			t.Errorf("expected no %s annotation from LoadArtifactFromReader, but it was set", ocispec.AnnotationTitle)
		}
	}
}

func TestLoadArtifactFromFile_FilenameExtractionFromPath(t *testing.T) {
	// Test that the filename is correctly extracted from various path formats
	// Since we can't easily test different paths to the same file, we just verify
	// that the existing test file produces the expected filename
	filePath := "../examples/artifact.example.json"
	expectedFilename := "artifact.example.json"
	mediaType := "application/json"

	// Call the function
	desc, _, err := LoadArtifactFromFile(filePath, mediaType)

	// Check that there was no error
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify that only the filename (not the path) is in the annotation
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

func TestAddFilenameAnnotationIfMissing_AddsAnnotationWhenMissing(t *testing.T) {
	// Test adding annotation when descriptor has no annotations
	desc := &ocispec.Descriptor{
		MediaType: "application/json",
		Size:      100,
		Digest:    "sha256:abc123",
	}
	filename := "../path/to/test-file.json"
	expectedFilename := "test-file.json"

	AddFilenameAnnotationIfMissing(desc, filename)

	// Check that annotations were created and title was set
	if desc.Annotations == nil {
		t.Fatalf("expected annotations to be created, got nil")
	}

	title, exists := desc.Annotations[ocispec.AnnotationTitle]
	if !exists {
		t.Errorf("expected annotation %s to exist", ocispec.AnnotationTitle)
	}
	if title != expectedFilename {
		t.Errorf("expected annotation %s to be '%s', got: %s", ocispec.AnnotationTitle, expectedFilename, title)
	}
}

func TestAddFilenameAnnotationIfMissing_AddsAnnotationWhenEmpty(t *testing.T) {
	// Test adding annotation when descriptor has empty annotations map
	desc := &ocispec.Descriptor{
		MediaType:   "application/json",
		Size:        100,
		Digest:      "sha256:abc123",
		Annotations: make(map[string]string),
	}
	filename := "test-file.json"
	expectedFilename := "test-file.json"

	AddFilenameAnnotationIfMissing(desc, filename)

	// Check that title annotation was added
	title, exists := desc.Annotations[ocispec.AnnotationTitle]
	if !exists {
		t.Errorf("expected annotation %s to exist", ocispec.AnnotationTitle)
	}
	if title != expectedFilename {
		t.Errorf("expected annotation %s to be '%s', got: %s", ocispec.AnnotationTitle, expectedFilename, title)
	}
}

func TestAddFilenameAnnotationIfMissing_AddsAnnotationWhenTitleEmpty(t *testing.T) {
	// Test adding annotation when descriptor has annotations but empty title
	desc := &ocispec.Descriptor{
		MediaType: "application/json",
		Size:      100,
		Digest:    "sha256:abc123",
		Annotations: map[string]string{
			"other.annotation":      "some-value",
			ocispec.AnnotationTitle: "", // Empty title
		},
	}
	filename := "C:\\Windows\\System32\\test-file.json"
	expectedFilename := "test-file.json"

	AddFilenameAnnotationIfMissing(desc, filename)

	// Check that title annotation was set
	title, exists := desc.Annotations[ocispec.AnnotationTitle]
	if !exists {
		t.Errorf("expected annotation %s to exist", ocispec.AnnotationTitle)
	}
	if title != expectedFilename {
		t.Errorf("expected annotation %s to be '%s', got: %s", ocispec.AnnotationTitle, expectedFilename, title)
	}

	// Check that other annotations are preserved
	other, exists := desc.Annotations["other.annotation"]
	if !exists || other != "some-value" {
		t.Errorf("expected other annotations to be preserved")
	}
}

func TestAddFilenameAnnotationIfMissing_PreservesExistingAnnotation(t *testing.T) {
	// Test that existing non-empty title annotation is preserved
	existingTitle := "existing-title.json"
	desc := &ocispec.Descriptor{
		MediaType: "application/json",
		Size:      100,
		Digest:    "sha256:abc123",
		Annotations: map[string]string{
			ocispec.AnnotationTitle: existingTitle,
			"other.annotation":      "some-value",
		},
	}
	filename := "new-filename.json"

	AddFilenameAnnotationIfMissing(desc, filename)

	// Check that existing title annotation was preserved
	title, exists := desc.Annotations[ocispec.AnnotationTitle]
	if !exists {
		t.Errorf("expected annotation %s to exist", ocispec.AnnotationTitle)
	}
	if title != existingTitle {
		t.Errorf("expected annotation %s to be preserved as '%s', got: %s", ocispec.AnnotationTitle, existingTitle, title)
	}

	// Check that other annotations are preserved
	other, exists := desc.Annotations["other.annotation"]
	if !exists || other != "some-value" {
		t.Errorf("expected other annotations to be preserved")
	}
}

func TestAddFilenameAnnotationIfMissing_HandlesVariousPathFormats(t *testing.T) {
	// Test that the function correctly extracts filenames from various path formats
	testCases := []struct {
		name         string
		inputPath    string
		expectedName string
	}{
		{
			name:         "relative path with slash",
			inputPath:    "../examples/test.json",
			expectedName: "test.json",
		},
		{
			name:         "simple filename",
			inputPath:    "test.json",
			expectedName: "test.json",
		},
		{
			name:         "absolute unix path",
			inputPath:    "/path/to/test.json",
			expectedName: "test.json",
		},
		{
			name:         "absolute windows path",
			inputPath:    "C:\\Windows\\System32\\test.json",
			expectedName: "test.json",
		},
		{
			name:         "current directory",
			inputPath:    "./test.json",
			expectedName: "test.json",
		},
		{
			name:         "windows style backslash",
			inputPath:    "examples\\test.json",
			expectedName: "test.json",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			desc := &ocispec.Descriptor{
				MediaType: "application/json",
				Size:      100,
				Digest:    "sha256:abc123",
			}

			AddFilenameAnnotationIfMissing(desc, tc.inputPath)

			// Check that the correct filename was extracted
			title, exists := desc.Annotations[ocispec.AnnotationTitle]
			if !exists {
				t.Errorf("expected annotation %s to exist", ocispec.AnnotationTitle)
			}
			if title != tc.expectedName {
				t.Errorf("for path '%s', expected annotation %s to be '%s', got: %s", tc.inputPath, ocispec.AnnotationTitle, tc.expectedName, title)
			}
		})
	}
}
