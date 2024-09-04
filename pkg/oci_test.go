package obom

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/registry"
)

func TestPushSBOM_Success_NoAttachArtifacts(t *testing.T) {
	// Create an in-memory target for testing
	memDest := memory.New()

	// Create a test SPDX document
	spdx := `{
		"SPDXID": "SPDXRef-DOCUMENT",
		"spdxVersion": "SPDX-2.3",
		"name" : "SPDX-Example",
		"creationInfo": {
				"created": "2020-07-23T18:30:22Z",
				"creators": ["Tool: SPDX-Java-Tools-v2.1.20", "Organization: Source Auditor Inc."],
				"licenseListVersion": "3.6"
		}
	}`
	reader := io.NopCloser(strings.NewReader(spdx))

	// Load the SPDX document from the reader
	doc, desc, sbomBytes, err := LoadSBOMFromReader(reader)

	// Check that there was no error
	if err != nil {
		t.Fatalf("expected no error from LoadSBOMFromReader, got: %v", err)
	}

	annotations, err := GetAnnotations(doc)
	if err != nil {
		t.Fatalf("expected no error from GetAnnotations, got: %v", err)
	}

	// Call the PushSBOM function
	sbomDesc, err := PushSBOM(doc, desc, sbomBytes, "localhost:5000/spdx:latest", annotations, false, nil, memDest)
	if err != nil {
		t.Fatalf("expected no error from PushSBOM, got: %v", err)
	}

	// Check that the returned descriptor has the expected digest
	if sbomDesc.Digest == "" {
		t.Errorf("expected descriptor digest to be set, got empty string")
	}

	ctx := context.Background()
	exists, err := memDest.Exists(ctx, *sbomDesc)
	if err != nil {
		t.Fatalf("error checking if sbom manifest exists: %v", err)
	}
	if !exists {
		t.Errorf("expected manifest to exist in memory store")
	}

	fetchedRc, err := memDest.Fetch(ctx, *sbomDesc)
	if err != nil {
		t.Fatalf("error fetching sbom manifest from memory store: %v", err)
	}

	var fetchedManifest ocispec.Manifest
	decoder := json.NewDecoder(fetchedRc)
	err = decoder.Decode(&fetchedManifest)
	if err != nil {
		t.Fatalf("error decoding fetched manifest: %v", err)
	}

	if fetchedManifest.Annotations[OCI_ANNOTATION_DOCUMENT_NAME] != "SPDX-Example" {
		t.Errorf("expected annotation %s to be 'SPDX-Example', got: %v", OCI_ANNOTATION_DOCUMENT_NAME, fetchedManifest.Annotations[OCI_ANNOTATION_DOCUMENT_NAME])
	}
	if fetchedManifest.Annotations[OCI_ANNOTATION_SPDX_VERSION] != "SPDX-2.3" {
		t.Errorf("expected annotation %s version to be 'SPDX-2.3', got: %v", OCI_ANNOTATION_SPDX_VERSION, fetchedManifest.Annotations[OCI_ANNOTATION_SPDX_VERSION])
	}
	if fetchedManifest.Annotations[OCI_ANNOTATION_CREATION_DATE] != "2020-07-23T18:30:22Z" {
		t.Errorf("expected annotation %s to be '2020-07-23T18:30:22Z', got: %v", OCI_ANNOTATION_SPDX_VERSION, fetchedManifest.Annotations[OCI_ANNOTATION_SPDX_VERSION])
	}

	// Check that the returned descriptor has the expected digest
	if sbomDesc.Digest == "" {
		t.Errorf("expected descriptor digest to be set, got empty string")
	}

	if sbomDesc.ArtifactType != MEDIATYPE_SPDX {
		t.Errorf("expected descriptor artifactType to be %s, got: %s", MEDIATYPE_SPDX, sbomDesc.ArtifactType)
	}
}

func TestPushSBOM_Success_WithAttachArtifacts(t *testing.T) {
	// Create an in-memory target for testing
	memDest := memory.New()

	// Create a test SPDX document
	spdx := `{
		"SPDXID": "SPDXRef-DOCUMENT",
		"spdxVersion": "SPDX-2.3",
		"name" : "SPDX-Example",
		"creationInfo": {
				"created": "2020-07-23T18:30:22Z",
				"creators": ["Tool: SPDX-Java-Tools-v2.1.20", "Organization: Source Auditor Inc."],
				"licenseListVersion": "3.6"
		}
	}`
	reader := io.NopCloser(strings.NewReader(spdx))

	// Load the SPDX document from the reader
	doc, desc, sbomBytes, err := LoadSBOMFromReader(reader)

	// Check that there was no error
	if err != nil {
		t.Fatalf("expected no error from LoadSBOMFromReader, got: %v", err)
	}

	attachArtifacts := map[string][]string{
		"application/json": {"../examples/artifact.example.json"},
		"application/yaml": {"../examples/artifact.example.yaml"},
	}

	// Call the PushSBOM function
	sbomDesc, err := PushSBOM(doc, desc, sbomBytes, "localhost:5000/spdx:latest", nil, false, attachArtifacts, memDest)
	if err != nil {
		t.Fatalf("expected no error from PushSBOM, got: %v", err)
	}

	// Check that the returned descriptor has the expected digest
	if sbomDesc.Digest == "" {
		t.Errorf("expected descriptor digest to be set, got empty string")
	}

	// Check that the sbom manifest has the expected referrer artifacts
	ctx := context.Background()
	referrers, err := registry.Referrers(ctx, memDest, *sbomDesc, "")
	if err != nil {
		t.Fatalf("error getting referrers: %v", err)
	}

	if len(referrers) != 2 {
		t.Errorf("expected 2 referrer artifacts, got: %d", len(referrers))
	}

	for _, referrer := range referrers {
		if referrer.ArtifactType != "application/json" && referrer.ArtifactType != "application/yaml" {
			t.Errorf("expected referrer artifactType to be 'application/json' or 'application/yaml', got: %s", referrer.ArtifactType)
		}
	}
}
