package obom

import (
	"fmt"
	"io"
	"os"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
)

func LoadArtifactFromFile(filename string, mediaType string) (*ocispec.Descriptor, []byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, nil, fmt.Errorf("error loading artifact from file: %w", err)
	}

	return LoadArtifactFromReader(file, mediaType)
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
