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

	// Extract just the filename without the path for the annotation
	baseFilename := filepath.Base(filename)
	return LoadArtifactFromReader(file, mediaType, baseFilename)
}

func LoadArtifactFromReader(reader io.ReadCloser, mediaType string, filename ...string) (*ocispec.Descriptor, []byte, error) {
	defer reader.Close()

	// Read all the bytes from the reader into a slice
	artifactBytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, err
	}

	desc := content.NewDescriptorFromBytes(mediaType, artifactBytes)

	// Add artifact filename annotation if filename is provided and not empty
	if len(filename) > 0 && filename[0] != "" {
		if desc.Annotations == nil {
			desc.Annotations = make(map[string]string)
		}
		desc.Annotations[ocispec.AnnotationTitle] = filename[0]
	}

	return &desc, artifactBytes, nil
}
