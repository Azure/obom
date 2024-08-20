package obom

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"
)

func TestAttachArtifact_Success(t *testing.T) {
	// Create an in-memory target for testing
	memDest := memory.New()
	ctx := context.Background()

	// Create a subject descriptor
	subjectArtifactType := "application/spdx"
	subjectDescriptor, err := oras.PackManifest(ctx, memDest, oras.PackManifestVersion1_1, subjectArtifactType, oras.PackManifestOptions{})
	if err != nil {
		t.Fatalf("error creating subject descriptor: %v", err)
	}

	testArtifact := "test signature"
	testArtifactType := "application/cose"

	// Create some artifact bytes
	artifactBytes := []byte(testArtifact)

	artifactReader := bytes.NewReader(artifactBytes)
	artifactDigest, err := getDigestFromReader(artifactReader)
	if err != nil {
		t.Fatalf("error getting digest from reader: %v", err)
	}

	// Create an artifact descriptor
	artifactDescriptor := v1.Descriptor{
		MediaType: testArtifactType,
		Digest:    artifactDigest,
		Size:      int64(len(artifactBytes)),
	}

	// Call the AttachArtifact function
	artifactManifest, err := AttachArtifact(&subjectDescriptor, &artifactDescriptor, testArtifactType, artifactBytes, memDest)

	// Check that there was no error
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	exists, err := memDest.Exists(ctx, *artifactManifest)
	if err != nil {
		t.Fatalf("error checking if manifest exists: %v", err)
	}
	if !exists {
		t.Errorf("expected manifest to exist in memory store")
	}

	fetchedRc, err := memDest.Fetch(ctx, *artifactManifest)
	if err != nil {
		t.Fatalf("error fetching manifest from memory store: %v", err)
	}
	// Unmarshal the fetched manifest
	var fetchedManifest v1.Manifest
	decoder := json.NewDecoder(fetchedRc)
	err = decoder.Decode(&fetchedManifest)
	if err != nil {
		t.Fatalf("error decoding fetched manifest: %v", err)
	}

	if fetchedManifest.Subject.Digest != subjectDescriptor.Digest {
		t.Errorf("expected fetched manifest subject digest to be %v, got: %v", subjectDescriptor.Digest, fetchedManifest.Subject.Digest)
	}

	// Check that the returned manifest has the expected artifactType
	if artifactManifest.ArtifactType != testArtifactType {
		t.Errorf("expected manifest artifactType to be '%s', got: %v", testArtifactType, artifactManifest.ArtifactType)
	}
}
