package obom

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"

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

// LoadSBOMFromFile opens a file given by filename, reads its contents, and loads it into an SPDX document.
// It also calculates the file size and generates an OCI descriptor for the file.
// It returns the loaded SPDX document, the OCI descriptor, and any error encountered.
func LoadSBOMFromFile(filename string) (*v2_3.Document, *oci.Descriptor, []byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, nil, nil, err
	}
	defer file.Close()

	fileSize, err := getFileSize(file)
	if err != nil {
		return nil, nil, nil, err
	}

	return LoadSBOMFromReader(file, fileSize)
}

// LoadSBOMFromReader reads an SPDX document from an io.ReadCloser, generates an OCI descriptor for the document,
// and returns the loaded SPDX document and the OCI descriptor.
// The size parameter is the size of the document in bytes.
// If an error occurs during reading the document or generating the descriptor, the error will be returned.
func LoadSBOMFromReader(reader io.ReadCloser, size int64) (*v2_3.Document, *oci.Descriptor, []byte, error) {
	defer reader.Close()

	// Read all the bytes from the reader into a slice
	sbomBytes, err := readAllBytes(reader)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create a bytes.Reader from the slice
	sbomReader := bytes.NewReader(sbomBytes)

	// Read the SPDX document from the reader
	doc, err := json.Read(sbomReader)
	if err != nil {
		return nil, nil, nil, err
	}

	// Reset the reader for the next read
	sbomReader.Reset(sbomBytes)

	// Generate the OCI descriptor for the SPDX document
	desc, err := getFileDescriptor(sbomReader, size)
	if err != nil {
		return nil, nil, nil, err
	}

	return doc, desc, sbomBytes, nil
}

func getFileDescriptor(reader io.Reader, size int64) (*oci.Descriptor, error) {
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

func readAllBytes(reader io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	_, err := io.Copy(&buf, reader)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
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
