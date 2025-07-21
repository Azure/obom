package obom

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

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

	// Check if the descriptor already has a title annotation, if not, add it
	if desc.Annotations == nil || desc.Annotations[ocispec.AnnotationTitle] == "" {
		if desc.Annotations == nil {
			desc.Annotations = make(map[string]string)
		}
		// Use only the base filename, not the full path
		desc.Annotations[ocispec.AnnotationTitle] = filepath.Base(filename)
	}

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
