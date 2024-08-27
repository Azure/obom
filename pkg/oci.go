package obom

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"

	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote/auth"
)

const (
	APPLICATION_USERAGENT = "obom"
)

type CredentialsResolver = func(context.Context, string) (auth.Credential, error)

// PushSBOM pushes the SPDX SBOM bytes to the registry as an OCI artifact.
// It takes in a pointer to an SPDX document, a pointer to a descriptor, a byte slice of the SBOM, a reference string, a map of SPDX annotations, and a credentials resolver function.
// It returns an error if there was an issue pushing the SBOM to the registry.
func PushSBOM(sbomDoc *v2_3.Document, sbomDescriptor *v1.Descriptor, sbomBytes []byte, reference string, spdx_annotations map[string]string, pushSummary bool, attachArtifacts map[string][]string, dest oras.Target) (*v1.Descriptor, error) {
	mem := memory.New()
	ctx := context.Background()

	// Create a Reader for the bytes
	sbomReader := bytes.NewReader(sbomBytes)

	// Add descriptor to a memory store
	err := mem.Push(ctx, *sbomDescriptor, sbomReader)
	if err != nil {
		return nil, fmt.Errorf("error pushing SBOM into memory store: %w", err)
	}

	layers := []v1.Descriptor{*sbomDescriptor}

	// Add annotations to the manifest
	annotations := make(map[string]string)
	for k, v := range spdx_annotations {
		annotations[k] = v
	}

	// add the summary blob as a layer if pushSummary is set
	if pushSummary {
		sbomSummary, err := GetSBOMSummary(sbomDoc)
		if err != nil {
			return nil, fmt.Errorf("error getting SBOM summary: %w", err)
		}
		// Marshal the summary into a string
		summaryBytes, err := json.Marshal(sbomSummary)
		if err != nil {
			return nil, fmt.Errorf("error marshaling summary into bytes: %w", err)
		}
		summaryDescriptor, err := oras.PushBytes(ctx, mem, "application/json", summaryBytes)
		if err != nil {
			return nil, fmt.Errorf("error pushing summary into memory store: %w", err)
		}
		layers = append(layers, summaryDescriptor)
	}

	// Pack the files and tag the packed manifest
	artifactType := MEDIATYPE_SPDX
	manifestDescriptor, err := oras.PackManifest(ctx, mem, oras.PackManifestVersion1_1, artifactType, oras.PackManifestOptions{
		Layers:              layers,
		ManifestAnnotations: annotations,
	})
	if err != nil {
		return nil, fmt.Errorf("error packing manifest: %w", err)
	}

	// Use the latest tag if no tag is specified
	tag := "latest"
	ref, err := registry.ParseReference(reference)
	if err != nil {
		return nil, fmt.Errorf("error parsing reference: %w", err)
	}

	if ref.Reference != "" {
		tag = ref.Reference
	}

	if err = mem.Tag(ctx, manifestDescriptor, tag); err != nil {
		return nil, err
	}

	if len(attachArtifacts) > 0 {
		for artifactType, paths := range attachArtifacts {
			for _, path := range paths {
				// load the artifact from the path
				artifactDesc, artifactBytes, err := LoadArtifactFromFile(path, artifactType)
				if err != nil {
					return nil, fmt.Errorf("error loading artifact: %v", err)
				}
				err = AttachArtifact(ctx, &manifestDescriptor, artifactDesc, artifactType, artifactBytes, mem)
				if err != nil {
					return nil, fmt.Errorf("error attaching artifact: %v", err)
				}
			}
		}
	}

	// Copy from the memory store to the remote repository
	manifest, err := oras.ExtendedCopy(ctx, mem, tag, dest, tag, oras.DefaultExtendedCopyOptions)
	return &manifest, err
}

// AttachArtifact attaches an artifact to the subject descriptor
func AttachArtifact(ctx context.Context, subject *v1.Descriptor, artifactDescriptor *v1.Descriptor, artifactType string, artifactBytes []byte, mem *memory.Store) error {
	// Create a Reader for the bytes
	artifactReader := bytes.NewReader(artifactBytes)

	// Add descriptor to a memory store
	err := mem.Push(ctx, *artifactDescriptor, artifactReader)
	if err != nil {
		return fmt.Errorf("error pushing artifact into memory store: %w", err)
	}

	// Pack the artifact manifest with the subject descriptor
	_, err = oras.PackManifest(ctx, mem, oras.PackManifestVersion1_1, artifactType, oras.PackManifestOptions{
		Subject: subject,
		Layers:  []v1.Descriptor{*artifactDescriptor},
	})

	if err != nil {
		return fmt.Errorf("error packing artifact manifest: %w", err)
	}

	return nil
}
