package obom

import (
	"os"

	"crypto/sha256"
	"encoding/hex"
	"io"

	"github.com/opencontainers/go-digest"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
	json "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

const (
	MEDIATYPE_SPDX                    = "application/spdx+json"
	OCI_ANNOTATION_DOCUMENT_NAME      = "org.spdx.name"
	OCI_ANNOTATION_DATA_LICENSE       = "org.spdx.license"
	OCI_ANNOTATION_DOCUMENT_NAMESPACE = "org.spdx.namespace"
	OCI_ANNOTATION_SPDX_VERSION       = "org.spdx.version"
	OCI_ANNOTATION_CREATION_DATE      = "org.spdx.created"
	OCI_ANNOTATION_ANNOTATOR          = "org.spdx.annotator"
	OCI_ANNOTATION_ANNOTATION_DATE    = "org.spdx.annotation_date"
)

func LoadSBOMFromFile(filename string) (*v2_3.Document, *oci.Descriptor, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	fileSize, err := getFileSize(file)
	if err != nil {
		return nil, nil, err
	}

	return LoadSBOMFromReader(file, fileSize)
}

// LoadSBOM loads an SPDX file into memory
func LoadSBOMFromReader(reader io.ReadCloser, size int64) (*v2_3.Document, *oci.Descriptor, error) {
	defer reader.Close()

	doc, err := json.Read(reader)
	if err != nil {
		return nil, nil, err
	}

	desc, err := getFileDescriptor(reader, size)
	if err != nil {
		return nil, nil, err
	}

	return doc, desc, nil
}

func getFileDescriptor(reader io.ReadCloser, size int64) (*oci.Descriptor, error) {
	// Create a new SHA256 hasher
	hasher := sha256.New()

	// Copy the file's contents into the hasher
	if _, err := io.Copy(hasher, reader); err != nil {
		return nil, err
	}

	// Get the resulting hash as a byte slice
	hash := hasher.Sum(nil)

	// Convert the hash to a hexadecimal string
	hashString := hex.EncodeToString(hash)

	d := digest.NewDigestFromHex("sha256", hashString)

	desc := &oci.Descriptor{
		MediaType: MEDIATYPE_SPDX,
		Digest:    d,
		Size:      size,
	}

	return desc, nil
}

func getFileSize(file *os.File) (int64, error) {
	// Get the file size
	fileInfo, err := file.Stat()
	if err != nil {
		return 0, err
	}

	return fileInfo.Size(), nil
}

// GetAnnotations returns the annotations from the SBOM
func GetAnnotations(sbom *v2_3.Document) (map[string]string, error) {
	annotations := make(map[string]string)

	annotations[OCI_ANNOTATION_DOCUMENT_NAME] = sbom.DocumentName
	annotations[OCI_ANNOTATION_DATA_LICENSE] = sbom.DataLicense
	annotations[OCI_ANNOTATION_DOCUMENT_NAMESPACE] = sbom.DocumentNamespace
	annotations[OCI_ANNOTATION_SPDX_VERSION] = sbom.SPDXVersion
	annotations[OCI_ANNOTATION_CREATION_DATE] = sbom.CreationInfo.Created

	return annotations, nil
}

// GetPackages returns the packages from the SBOM
func GetPackages(sbom *v2_3.Document) ([]string, error) {
	var packages []string

	for _, pkg := range sbom.Packages {
		if pkg.PackageExternalReferences != nil {
			for _, exRef := range pkg.PackageExternalReferences {
				packages = append(packages, exRef.Locator)
			}
		}
	}

	return packages, nil
}

func GetFiles(sbom *v2_3.Document) ([]string, error) {
	var files []string

	for _, file := range sbom.Files {
		files = append(files, file.FileName)
	}

	return files, nil
}
