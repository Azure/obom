package obom

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	credentials "github.com/oras-project/oras-credentials-go"

	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/content/memory"

	// "oras.land/oras-go/v2/content/reader"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"
)

const (
	APPLICATION_USERAGENT = "obom"
)

type CredentialsResolver = func(context.Context, string) (auth.Credential, error)

// PushFiles pushes the SPDX SBOM file to the registry
func PushFiles(filename string, reference string, spdx_annotations map[string]string, username string, password string) error {

	// 0. Create a file store
	fs, err := file.New(".")
	if err != nil {
		return err
	}
	defer fs.Close()
	ctx := context.Background()

	// Add files to a file store
	mediaType := MEDIATYPE_SPDX
	fileNames := []string{filename}
	fileDescriptors := make([]v1.Descriptor, 0, len(fileNames))
	for _, name := range fileNames {
		fileDescriptor, err := fs.Add(ctx, name, mediaType, "")
		if err != nil {
			return err
		}
		fileDescriptors = append(fileDescriptors, fileDescriptor)
		fmt.Printf("Adding %s: %s\n", name, fileDescriptor.Digest)
	}

	annotations := make(map[string]string)
	for k, v := range spdx_annotations {
		annotations[k] = v
	}

	//Pack the files and tag the packed manifest
	artifactType := MEDIATYPE_SPDX
	manifestDescriptor, err := oras.Pack(ctx, fs, artifactType, fileDescriptors, oras.PackOptions{
		PackImageManifest:   true,
		ManifestAnnotations: annotations,
	})
	if err != nil {
		return err
	}

	// Use the latest tag isf no tag is specified
	tag := "latest"
	ref, err := registry.ParseReference(reference)
	if err != nil {
		return err
	}

	if ref.Reference != "" {
		tag = ref.Reference
	}
	fmt.Printf("Pushing %s/%s:%s %s\n", ref.Registry, ref.Repository, tag, manifestDescriptor.Digest)
	if err = fs.Tag(ctx, manifestDescriptor, tag); err != nil {
		return err
	}

	//Connect to a remote repository
	repo, err := remote.NewRepository(reference)
	if err != nil {
		panic(err)
	}

	// Check if registry has is localhost or starts with localhost:
	reg := repo.Reference.Registry
	if strings.HasPrefix(reg, "localhost:") {
		repo.PlainHTTP = true
	}

	// Prepare the auth client for the registry
	client := &auth.Client{
		Client: retry.DefaultClient,
		Cache:  auth.DefaultCache,
	}

	if len(username) != 0 && len(password) != 0 {
		client.Credential = auth.StaticCredential(reg, auth.Credential{
			Username: username,
			Password: password,
		})
	} else {
		storeOpts := credentials.StoreOptions{}
		store, err := credentials.NewStoreFromDocker(storeOpts)
		if err != nil {
			return err
		}

		client.Credential = credentials.Credential(store)
	}

	client.SetUserAgent(APPLICATION_USERAGENT)
	repo.Client = client

	//Copy from the file store to the remote repository
	_, err = oras.Copy(ctx, fs, tag, repo, tag, oras.DefaultCopyOptions)
	return err
}

// PushSBOM pushes the SPDX SBOM bytes to the registry
func PushSBOM(sbomDoc *v2_3.Document, sbomDescriptor *v1.Descriptor, sbomBytes []byte, reference string, spdx_annotations map[string]string, credsResolver CredentialsResolver) error {
	mem := memory.New()
	ctx := context.Background()

	// Add bytes to a reader
	sbomReader := bytes.NewReader(sbomBytes)

	// Add descriptor to a memory store
	err := mem.Push(ctx, *sbomDescriptor, sbomReader)
	if err != nil {
		return fmt.Errorf("error pushing image into memory store: %w", err)
	}

	annotations := make(map[string]string)
	for k, v := range spdx_annotations {
		annotations[k] = v
	}

	//Pack the files and tag the packed manifest
	artifactType := MEDIATYPE_SPDX
	descriptors := []v1.Descriptor{*sbomDescriptor}
	manifestDescriptor, err := oras.Pack(ctx, mem, artifactType, descriptors, oras.PackOptions{
		PackImageManifest:   true,
		ManifestAnnotations: annotations,
	})
	if err != nil {
		return fmt.Errorf("error packing image: %w", err)
	}

	// Use the latest tag isf no tag is specified
	tag := "latest"
	ref, err := registry.ParseReference(reference)
	if err != nil {
		return fmt.Errorf("error parsing reference: %w", err)
	}

	if ref.Reference != "" {
		tag = ref.Reference
	}
	fmt.Printf("Pushing %s/%s:%s %s\n", ref.Registry, ref.Repository, tag, manifestDescriptor.Digest)
	if err = mem.Tag(ctx, manifestDescriptor, tag); err != nil {
		return err
	}

	//Connect to a remote repository
	repo, err := remote.NewRepository(reference)
	if err != nil {
		panic(fmt.Errorf("error connecting to remote repository: %w", err))
	}

	// Check if registry has is localhost or starts with localhost:
	reg := repo.Reference.Registry
	if strings.HasPrefix(reg, "localhost:") {
		repo.PlainHTTP = true
	}

	// Prepare the auth client for the registry
	client := &auth.Client{
		Client: retry.DefaultClient,
		Cache:  auth.DefaultCache,
	}

	client.Credential = credsResolver

	client.SetUserAgent(APPLICATION_USERAGENT)
	repo.Client = client

	// Copy from the memory store to the remote repository
	_, err = oras.Copy(ctx, mem, tag, repo, tag, oras.DefaultCopyOptions)
	return err
}
