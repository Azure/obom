package obom

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
)

func LoadArtifactFromFile(filename string, mediaType string) (*ocispec.Descriptor, []byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, nil, fmt.Errorf("error loading artifact from file: %w", err)
	}

	desc, artifactBytes, err := LoadArtifactFromReader(file, mediaType)
	if err != nil {
		return nil, nil, err
	}

	// Add filename annotation if missing
	AddFilenameAnnotationIfMissing(desc, filename)

	return desc, artifactBytes, nil
}

func LoadArtifactFromReader(reader io.ReadCloser, mediaType string) (*ocispec.Descriptor, []byte, error) {
	defer reader.Close()

	// Read all the bytes from the reader into a slice
	artifactBytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, err
	}

	desc := content.NewDescriptorFromBytes(mediaType, artifactBytes)

	return &desc, artifactBytes, nil
}

// AddFilenameAnnotationIfMissing adds a title annotation to the descriptor using the base filename
// if the annotation doesn't already exist or is empty. This function modifies the descriptor in-place.
func AddFilenameAnnotationIfMissing(desc *ocispec.Descriptor, filename string) {
	if desc.Annotations == nil || desc.Annotations[ocispec.AnnotationTitle] == "" {
		if desc.Annotations == nil {
			desc.Annotations = make(map[string]string)
		}
		// Use only the base filename, not the full path
		// Handle both Unix and Windows path separators regardless of platform
		basename := filepath.Base(filename)
		// If filepath.Base didn't extract properly (e.g., Windows paths on Unix), try manual extraction
		if lastSlash := strings.LastIndexByte(basename, '\\'); lastSlash >= 0 {
			basename = basename[lastSlash+1:]
		}
		desc.Annotations[ocispec.AnnotationTitle] = basename
	}
}
