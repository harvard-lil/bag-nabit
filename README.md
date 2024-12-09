bag-nabit
=========

![Test Status](https://github.com/harvard-lil/bag-nabit/actions/workflows/test.yml/badge.svg)

`bag-nabit` is a tool for downloading and attaching provenance information to public datasets.
The tool is intended for library projects that back up public domain resources and share
them with patrons.

`bag-nabit` writes a dialect of [BagIt](https://en.wikipedia.org/wiki/BagIt)
from either local files or remote URLs, and can also:

* Store request and response headers in a headers.warc file.
* Attach timestamps and public-key signatures to the bag's tagmanifest file.
* Verify format compliance and provenance chains on an existing bag-nabit bag.

Design goals
------------

`bag-nabit` is designed for researchers who want to use copies of public data
downloaded from libraries and archives, and be able to verify the provenance of downloaded data
if necessary. A typical scenario would be a library providing a copy of a government dataset where funding has expired and the dataset is no longer available from the original source.

The tool is inspired by the 
[WARC](https://en.wikipedia.org/wiki/Web_ARChive) and 
[wacz-auth](https://specs.webrecorder.net/wacz-auth/0.1.0/) formats,
by [bagit-python](https://github.com/LibraryOfCongress/bagit-python),
and by the [C2PA](https://github.com/contentauth/c2patool) format for attaching provenance information to media files.

Design goals are:

* Usability:
  * Bags should be usable for capturing both web content and file content delivered out of band.
  * Bag content should be directly usable. For example, an archived CSV file should be readable as a CSV, rather than requiring a web archive reader.
* Transportability and self-documentation:
  * Users should be able to read metadata as a text file.
  * Avoid depending on custom file formats and tooling for consuming bags. As much as possible, bags should be composed of standard file formats verifiable with existing tools. Notably, use standard WARC files for headers and standard openssl commands for signatures and timestamps.
* Integrity and provenance:
  * Archivists should be able to vouch for a bag when creating it. Like C2PA and wacz-auth, bags should include certificate chains showing who (based on control of a private key) vouches for the integrity of the dataset.
  * Bags should be easy to copy and back up in different archives. Vouching should continue to work after a particular archive goes offline. We therefore rely on the existing PKI infrastructure (such as email, domain, and document signing certificates) to establish the identity of the signer.
  * Like WARC, users should be able to access request and response headers for the original source of data.

Installation
------------

`bag-nabit` is not yet available on PyPI, but can be installed from source:

```
pip install https://github.com/harvard-lil/bag-nabit/archive/refs/heads/main.zip
```

Or installed as a tool by [uv](https://docs.astral.sh/uv/):

```
uv tool install --from git+https://github.com/harvard-lil/bag-nabit nabit
```

Or run from [uvx](https://docs.astral.sh/uv/):

```
uvx --from git+https://github.com/harvard-lil/bag-nabit nabit --help
```

Quick start
------------

Create a bag from a single URL:

```
nabit archive example_bag -u https://example.com/
```

Create a bag from multiple URLs, files, and directories:

```
nabit archive example_bag -u https://example.com/ -u https://example.com/other -p /path/to/local/files
```

Create a bag with metadata headers:

```
nabit archive example_bag -u https://example.com/ -i "Title:Example Dataset"
```

Create a bag with a timestamp:

```
nabit archive example_bag -u https://example.com/ -t digicert
```

Create a bag with multiple signatures and a timestamp:

```
nabit archive example_bag -u https://example.com/ -s mykey.pem:mychain.pem -s anotherkey.pem:anotherchain.pem -t digicert
```

Amend an existing bag to add files, metadata, signatures, and/or timestamps (editing data will remove existing signatures):

```
nabit archive example_bag --amend -u https://example.com/another -i "Subtitle: Another Header" -s mykey.pem:mychain.pem -t digicert
```

Validate a bag's contents:

```
nabit validate example_bag
```

Command line usage
------------------
<!-- usage start -->
```
Usage:  [OPTIONS] COMMAND [ARGS]...

  BagIt package signing tool

Options:
  --help  Show this message and exit.

Commands:
  archive   Archive files and URLs into a BagIt package.
  validate  Validate a BagIt package.
```

### archive
```
Usage:  [OPTIONS] BAG_PATH

  Archive files and URLs into a BagIt package. bag_path is the destination
  directory for the package.

Options:
  -a, --amend                     Update an existing archive. May add OR
                                  OVERWRITE existing data.
  -u, --url TEXT                  URL to archive (can be repeated). May be a
                                  bare url or a JSON dict with a "url" key and
                                  an optional "output" key
  -p, --path TEXT                 File or directory to archive (can be
                                  repeated). May be a bare path or a JSON dict
                                  with a "path" key and an optional "output"
                                  key
  -c, --collect TEXT              Collection tasks in JSON format
  --hard-link                     Use hard links when copying files (when
                                  possible)
  -i, --info TEXT                 bag-info.txt metadata in key:value format
                                  (can be repeated)
  --signed-metadata FILE          JSON file to be copied to data/signed-
                                  metadata.json
  --unsigned-metadata FILE        JSON file to be copied to unsigned-
                                  metadata.json
  --signed-metadata-json TEXT     JSON string to be written to data/signed-
                                  metadata.json
  --unsigned-metadata-json TEXT   JSON string to be written to unsigned-
                                  metadata.json
  -s, --sign <cert_chain>:<key_file>
                                  Sign using certificate chain and private key
                                  files (can be repeated)
  -t, --timestamp <tsa_keyword> | <cert_chain>:<url>
                                  Timestamp using either a TSA keyword or a
                                  cert chain path and URL (can be repeated)
  --timeout FLOAT                 Timeout for collection tasks (default: 5.0)
  --collect-errors [fail|ignore]  How to handle collection task errors
                                  (default: fail)
  --help                          Show this message and exit.
```

### validate
```
Usage:  [OPTIONS] BAG_PATH

  Validate a BagIt package. bag_path is the path to the package directory to
  validate.

Options:
  --help  Show this message and exit.
```

<!-- usage end -->

Usage tips
----------

### Manual bag creation and editing

After creating a bag, or obtaining a bag from another source, the bag can be edited manually --
for example, by adding files to the data/ directory or editing a metadata file. However, new
data files or edits to signed files will invalidate the signature, causing `nabit validate` to fail.

To re-sign a bag after editing, use the `--amend` flag to `nabit archive`:

```
nabit archive example_bag --amend -s mykey.pem:mychain.pem -t digicert
```

This command will regenerate the manifest files, remove any signatures and timestamps that no
longer validate, and then re-run the signing and timestamping process.

### Key management: create-and-sign workflows

Bags can be signed with any key accepted by `openssl cms`, such as domain keys, email keys, or
document signing keys. Protecting these keys is very important, as losing them will not only
allow an attacker to create fake bags, but also to publish fake websites, email, or whatever
other purpose the key serves.

In many situations it may make sense to create and sign bags on different machines or by different people. A typical workflow might be:

* A worker machine or trusted volunteer creates the bag and timestamps it, but does not sign it:
  ```
  nabit archive example_bag -u https://example.com/ -t digicert
  ```
* The data is transferred to a high security machine where a signature and a second timestamp is added:
  ```
  nabit archive example_bag --amend -s mykey.pem:mychain.pem -t digicert
  ```
* The signed bag is then published to the archive, perhaps simply by copying the bag directory to a public file server.

### Security warning: collecting untrusted URLs

It is not recommended to collect URLs from untrusted sources without validating their destination.

`bag-nabit` currently WILL capture URLs that point to local IP addresses, such as localhost or the local network.
This is a security risk, as it may allow an attacker to capture sensitive data from local networks, especially on
cloud hosting where known URLs may share sensitive configuration data.

Collection backends
-------------------

`bag-nabit` is not primarily a web archiving tool, but it supports collection backends that can gather both web content and file content. Collection tasks can be provided as JSON content passed to the `--collect` flag to `nabit archive`:

```
nabit archive example_bag --collect '[
  {"backend": "url", "url": "https://example.com/", "output": "example_com.html"},
  {"backend": "path", "path": "/path/to/local/file"}
]'
```

Currently supported collection backends are:

* `url`: fetch URLs with python `requests`, following redirects. Write metadata to data/headers.warc. Equivalent to the `-u` flag to `nabit archive`. Keys:
  * `url`: the URL to fetch
  * `output` (optional): the path to save the fetched content to in the bag, relative to `data/files/`. If not provided, the content will be saved to `data/files/<url_path>`, where `<url_path>` is the last path component of the URL.
* `path`: copy local files or directories to the bag. Equivalent to the `-p` flag to `nabit archive`. Keys:
  * `path`: the path to the local file or directory to copy
  * `output` (optional): the path to save the fetched content to in the bag.

Future backends could include ftp, web crawlers, etc.

File format
-----------

`bag-nabit` reads and writes a special dialect of [BagIt](https://en.wikipedia.org/wiki/BagIt) designed for attaching provenance to publicly hosted resources.

`bag-nabit`-flavored bags have the following notable features:

* headers.warc records provenance information for files downloaded from the web.
* signatures/ contains a chain of signature files and timestamp files for the tagmanifest.
* standard locations for metadata that is either signed with the bag, or editable after the bag is created.

The layout of a `bag-nabit` bag is as follows:

* `bagit.txt`: standard BagIt file
* `bag-info.txt`: standard BagIt file
* `manifest-sha256.txt`: standard BagIt file
* `tagmanifest-sha256.txt`: standard BagIt file
* `unsigned-metadata.json`: optional metadata, not signed, editable after bag is created
* `data/`
  * `files/`: directory of files added to the bag
    * `...`
  * `headers.warc`: optional, request and response headers from HTTP fetches for files in `files/`
  * `signed-metadata.json`: optional metadata, signed along with the bag contents
* `signatures/`: directory of signature files
  * `tagmanifest-sha256.txt.p7s` -- signature file for `tagmanifest-sha256.txt`
  * `tagmanifest-sha256.txt.p7s.tsr` -- timestamp file for `tagmanifest-sha256.txt.p7s`
  * `tagmanifest-sha256.txt.p7s.tsr.crt` -- certificate file for `tagmanifest-sha256.txt.p7s.tsr`
  * `...` -- other signature files in chain

### headers.warc format

headers.warc is a standard [WARC](https://en.wikipedia.org/wiki/Web_ARChive) file containing request and 
response headers from HTTP fetches for files in `data/files/`.

headers.warc is not required to exist, and if it exists, may not include entries for every file in `data/files/`.
This allows `bag-nabit` to be used both for resources accessible via HTTP and otherwise.

Response records in headers.warc are stored as Revisit records, using a custom WARC-Profile header
as [allowed by the WARC specification](https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1/#revisit):

```
WARC-Type: revisit
WARC-Profile: file-content; filename="files/data.html"
```

### `signatures/` directory format

The `signatures/` directory contains a chain of signature files and timestamp files for the tagmanifest.

Signing the tagmanifest file is sufficient to ensure the integrity of the bag, as the tagmanifest contains
cryptographic hashes for all tag files, including the manifest file which contains hashes for all data files.

The signatures directory can contain two kinds of attestation files:
* `.p7s` files are PKCS#7 signature files, which assert a domain or email address vouching for the bag contents.
  * `.p7s` files are created with the command:
    ```
    openssl cms -sign -binary -md sha256 -in <original_file> -out <signature_file> -inkey <key_file> -signer <first_cert> [-certfile <remaining_chain>] -outform PEM -nosmimecap -cades
    ```
  * `.p7s` files can be validated with the command:
    ```
    openssl cms -verify -binary -content <original_file> -in <signature_file> -inform PEM -purpose any
    ```
* `.tsr` files are timestamp response files, which assert a time before which the bag was created.
  * `.tsr` files are created with the command:
    ```
    openssl ts -query -data <original_file> -sha256 -cert
    ```
  * `.tsr` files can be validated with the commands:
    ```
    # verify certificate chain
    openssl verify <certificate_file>
    # validate timestamp
    openssl ts -verify -data <original_file> -in <timestamp_file> -CAfile <certificate_file>
    ```
  
To allow creation of arbitrary certificate chains, each attestation includes the full file name of the file it attests to.
For example, this layout:

```
tagmanifest-sha256.txt
signatures/
  tagmanifest-sha256.txt.p7s
  tagmanifest-sha256.txt.p7s.tsr
  tagmanifest-sha256.txt.p7s.tsr.crt
```

indicates that the signature in `tagmanifest-sha256.txt.p7s` attests to the integrity of `tagmanifest-sha256.txt`,
and the timestamp in `tagmanifest-sha256.txt.p7s.tsr`, whose TSA uses the certificate chain in `tagmanifest-sha256.txt.p7s.tsr.crt`,
attests to the time `tagmanifest-sha256.txt.p7s` was created.

*Note:* As of this version, there is no way for a signer to attach metadata (such as intents) to a signature.
Therefore all signatures are understood to vouch for the contents of the entire bag.

*Note:* Signatures SHOULD always be followed by a timestamp, so that the final interpretation of a signature chain is:
"the controller of this email address/domain, at or before this time, vouch for the contents of the bag".

*Note:* Bags created by `bag-nabit` include only the base tag files (bagit.txt, bag-info.txt, manifest-sha256.txt)
in the `tagmanifest-sha256.txt` file, which is allowed but not encouraged by the BagIt spec. This is to allow
unsigned metadata outside the data/ directory.

### metadata format

The BagIt specification allows minimal metadata to be stored in the bag-info.txt file,
and any extensive metadata to be stored within the data/ directory.
Headers can be added to bag-info.txt with the `--info / -i` flag to `nabit archive`.

To clarify the distinction between **signed** and **unsigned** metadata, `bag-nabit` extends
this specification to encourage metadata to be stored in two files:

* `data/signed-metadata.json`: metadata signed with the bag.
* `unsigned-metadata.json`: metadata not signed, editable after bag is created.

In practice *any* files within data/ will be signed, and any files outside data/ will not,
but the provided filenames are encouraged to ensure that users will understand the distinction.

`bag-nabit` does not currently specify anything regarding the
contents of the metadata files.

Development
-----------

We use [uv](https://docs.astral.sh/uv/) to manage development dependencies. After cloning the repository, to run from source:

```
uv run nabit
```

This will automatically install dependencies and run the command.

To run tests:

```
uv run pytest
```

Some tests use the [inline-snapshot](https://github.com/15r10nk/inline-snapshot/) library. If the tool output changes
intentionally, you may need to run `uv run pytest --inline-snapshot=review` to review the changes and apply them
to test files.

After making changes to the command line interface, run `uv run scripts/update_docs.py` to update README.md.

Limitations and Caveats
-----------------------

* Currently only SHA-256 is supported for hashing. This is only out of expediency,
  and could be extended to other cryptographically secure hashes.
* Because empty directories are not included in BagIt manifest files, signatures
  do not verify the presence or absence of empty directories.
