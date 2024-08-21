package obom

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
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
	artifactBytes, err := readAllBytes(reader)
	if err != nil {
		return nil, nil, err
	}

	desc := getOCIDescriptor(mediaType, artifactBytes)

	return desc, artifactBytes, nil
}

func getOCIDescriptor(mediaType string, bytes []byte) *ocispec.Descriptor {
	desc := &ocispec.Descriptor{
		MediaType: mediaType,
		Digest:    digest.FromBytes(bytes),
		Size:      int64(len(bytes)),
	}

	return desc
}

func readAllBytes(reader io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	_, err := io.Copy(&buf, reader)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
