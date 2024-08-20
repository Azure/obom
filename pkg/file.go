package obom

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/opencontainers/go-digest"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
)

func LoadArtifactFromFile(filename string, mediaType string) (*oci.Descriptor, []byte, error) {
	file, fileSize, err := loadFile(filename)
	if err != nil {
		return nil, nil, fmt.Errorf("error loading artifact from file: %w", err)
	}

	return LoadArtifactFromReader(file, mediaType, fileSize)
}

func LoadArtifactFromReader(reader io.ReadCloser, mediaType string, fileSize int64) (*oci.Descriptor, []byte, error) {
	defer reader.Close()

	// Read all the bytes from the reader into a slice
	artifactBytes, err := readAllBytes(reader)
	if err != nil {
		return nil, nil, err
	}

	artifactReader := bytes.NewReader(artifactBytes)

	desc, err := getFileDescriptor(mediaType, artifactReader, fileSize)
	if err != nil {
		return nil, nil, err
	}

	return desc, artifactBytes, nil
}

func loadFile(filename string) (*os.File, int64, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, 0, err
	}
	// defer file.Close()

	fileSize, err := getFileSize(file)
	if err != nil {
		return nil, 0, err
	}

	return file, fileSize, nil
}

func getFileSize(file *os.File) (int64, error) {
	// Get the file size
	fileInfo, err := file.Stat()
	if err != nil {
		return 0, err
	}

	return fileInfo.Size(), nil
}

func getFileDescriptor(mediaType string, reader io.Reader, size int64) (*oci.Descriptor, error) {
	d, err := getDigestFromReader(reader)
	if err != nil {
		return nil, err
	}

	desc := &oci.Descriptor{
		MediaType: mediaType,
		Digest:    d,
		Size:      size,
	}

	return desc, nil
}

func getDigestFromReader(reader io.Reader) (digest.Digest, error) {
	// Create a new SHA256 hasher
	hasher := sha256.New()

	// Copy the file's contents into the hasher
	if _, err := io.Copy(hasher, reader); err != nil {
		return digest.NewDigestFromBytes(digest.SHA256, make([]byte, 0)), err
	}

	// Get the resulting hash as a byte slice
	hash := hasher.Sum(nil)

	// Convert the hash to a hexadecimal string
	hashString := hex.EncodeToString(hash)

	return digest.NewDigestFromEncoded(digest.SHA256, hashString), nil
}

func readAllBytes(reader io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	_, err := io.Copy(&buf, reader)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
