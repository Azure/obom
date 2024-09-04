# SPDX to OCI Artifact

This is a simple tool to convert an SPDX to a OCI Artifact and push the SPDX doc to an OCI registry with annotations.

## Build

Run `make` to build the binary or use the following command to build the binary.

```bash
go build -ldflags "-s -w" -o obom main.go
```

## Install

```bash
go get github.com/Azure/obom
```

## Usage

```
  obom [command] 
```

## Sub Commands 

- [obom show](#obom-show) - Show SPDX Document
- [obom push](#obom-push) - Push SPDX Document to OCI Registry
- [obom packages](#obom-packages) - List Packages
- [obom files](#obom-files) - List Files

### obom show

Sub command that shows the SPDX Document summary.

```bash
$ obom show -f ./examples/SPDXJSONExample-v2.3.spdx.json
================================================================================
Document Name:         SPDX-Tools-v2.0
DataLicense:           CC0-1.0
Document Namespace:    http://spdx.org/spdxdocs/spdx-example-444504E0-4F89-41D3-9A0C-0305E82C3301
SPDX Version:          SPDX-2.3 # NOTE This is the default version for all spdx you have to comment out line 76 
                                # from go\pkg\mod\github.com\spdx\tools-golang@v0.5.0\spdx\v2\v2_3\document.go
                                # in order to pull the correct version from the actual SPDX JSON
Creation Date:         2010-01-29T18:30:22Z
Creators:              LicenseFind-1.0
                       ExampleCodeInspect ()
                       Jane Doe ()
Packages:              4
Files:                 5
Digest:                sha256:2de3741a7be1be5f5e54e837524f2ec627fedfb82307dc004ae03b195abc092f
================================================================================
```

### obom push

Sub command that pushes the SPDX Document to an OCI registry and adds annotations to the OCI Artifact.
Annotations are the SPDX Document properties and can be overriden by the command line flags.


```bash
$ obom push -f ./examples/SPDXJSONExample-v2.3.spdx.json localhost:5001/spdx:example
================================================================================
Document Name:         SPDX-Tools-v2.0
Document Namespace:    http://spdx.org/spdxdocs/spdx-example-444504E0-4F89-41D3-9A0C-0305E82C3301
SPDX Version:          SPDX-2.3
Creation Date:         2010-01-29T18:30:22Z
Creators:              LicenseFind-1.0
                       ExampleCodeInspect ()
                       Jane Doe ()
Packages:              4
Files:                 5
Digest:                sha256:2de3741a7be1be5f5e54e837524f2ec627fedfb82307dc004ae03b195abc092f
================================================================================
Pushing SBOM to localhost:5000/spdx:example@sha256:2de3741a7be1be5f5e54e837524f2ec627fedfb82307dc004ae03b195abc092f...
SBOM pushed to localhost:5000/spdx:example@sha256:e28661b0beea56f0a256abca303b4d4506b7961542ebb78cc987aad9975e8b4b
```

You can view the manifest of the pushed artifact using the following command.

```bash
$ oras manifest get localhost:5001/spdx/annotations:test --pretty
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "text/spdx",
    "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    "size": 2
  },
  "layers": [
    {
      "mediaType": "text/spdx",
      "digest": "sha256:2de3741a7be1be5f5e54e837524f2ec627fedfb82307dc004ae03b195abc092f",
      "size": 21342,
      "annotations": {
        "org.opencontainers.image.title": "./examples/SPDXJSONExample-v2.3.spdx.json"
      }
    }
  ],
  "annotations": {
    "org.opencontainers.image.created": "2023-05-10T19:43:14Z",
    "org.spdx.license": "CC0-1.0",
    "org.spdx.name": "SPDX-Tools-v2.0",
    "org.spdx.namespace": "http://spdx.org/spdxdocs/spdx-example-444504E0-4F89-41D3-9A0C-0305E82C3301",
    "org.spdx.version": "SPDX-2.3"
  }
}
```

Artifacts can be attached via [OCI referrer artifacts](https://oras.land/docs/concepts/reftypes) using the --attach flag using the format of `artifactType=/path/to/artifact`. For example:

```bash
$ obom push -f ./examples/SPDXJSONExample-v2.3.spdx.json localhost:5000/spdx:example --attach application/json=./examples/artifact.example.json --attach application/yaml=./examples/artifact.example.yaml
================================================================================
Document Name:         SPDX-Tools-v2.0
Document Namespace:    http://spdx.org/spdxdocs/spdx-example-444504E0-4F89-41D3-9A0C-0305E82C3301
SPDX Version:          SPDX-2.3
Creation Date:         2010-01-29T18:30:22Z
Creators:              LicenseFind-1.0
                       ExampleCodeInspect ()
                       Jane Doe ()
Packages:              4
Files:                 5
Digest:                sha256:2de3741a7be1be5f5e54e837524f2ec627fedfb82307dc004ae03b195abc092f
================================================================================
Pushing SBOM to localhost:5000/spdx:example@sha256:2de3741a7be1be5f5e54e837524f2ec627fedfb82307dc004ae03b195abc092f...
SBOM pushed to localhost:5000/spdx:example@sha256:a1f469bf749c1643b8d73848e237c29df0fb5b4490bbd86dfb05d064c72fa645
```
You can view the attached artifacts using the following command:

```bash
$ oras discover localhost:5000/spdx:example@sha256:a1f469bf749c1643b8d73848e237c29df0fb5b4490bbd86dfb05d064c72fa645
localhost:5000/spdx@sha256:a1f469bf749c1643b8d73848e237c29df0fb5b4490bbd86dfb05d064c72fa645
├── application/yaml
│   └── sha256:f98e4542256fd718b95c0c785e97ccb3e24d17047e89bf3dab6193a205f11bd3
└── application/json
    └── sha256:afc2028285e3eb82c782beb4d7d188515e6a87b3a4d8bd69cc8df9a3686442ff
```

## obom packages

Subcommand that lists the packages in the SPDX Document. 

```shell
$ obom packages -f ./temp/manifest.spdx.json | head -5
pkg:nuget/Microsoft.Extensions.Configuration.Json@3.1.4
pkg:nuget/Microsoft.Extensions.FileProviders.Abstractions@3.1.4
pkg:nuget/Microsoft.Extensions.Configuration.Binder@3.1.4
pkg:nuget/Microsoft.Azure.Storage.Blob@11.1.2
pkg:nuget/Microsoft.Azure.Storage.File@11.1.2
```

## obom files

Subcommand that lists the files in the SPDX Document.

```shell
obom files -f ./examples/SPDXJSONExample-v2.3.spdx.json
./src/org/spdx/parser/DOAPProject.java
./lib-source/commons-lang3-3.1-sources.jar
./lib-source/jena-2.6.3-sources.jar
./docs/myspec.pdf
./package/foo.c
```
