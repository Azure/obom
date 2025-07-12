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

	return LoadArtifactFromReader(file, mediaType, filename)
}

func LoadArtifactFromReader(reader io.ReadCloser, mediaType string, name string) (*ocispec.Descriptor, []byte, error) {
	defer reader.Close()

	// Read all the bytes from the reader into a slice
	artifactBytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, err
	}

	desc := content.NewDescriptorFromBytes(mediaType, artifactBytes)

	// Add artifact name annotation if name is provided and not empty
	if name != "" {
		if desc.Annotations == nil {
			desc.Annotations = make(map[string]string)
		}
		desc.Annotations[ocispec.AnnotationTitle] = name
	}

	return &desc, artifactBytes, nil
}
