bag-nabit
=========

`bag-nabit` is a tool for downloading and attaching provenance to public datasets.
The tool is intended for library projects that back up public domain resources and share
them with patrons.

`bag-nabit` writes a bagit package from either local files or remote URLs, and can also:

* Store request and response headers in a headers.warc file.
* Attach timestamps and public-key signatures to the bag's tagmanifest file.

Installation
------------

`bag-nabit` is not yet available on PyPI, but can be installed from source:

```
pip install https://github.com/harvard-lil/bag-nabit/archive/refs/heads/main.zip
```

Or run from [uvx](https://docs.astral.sh/uv/):

```
uvx --from git+https://github.com/harvard-lil/bag-nabit nabit --help
```

Quick start
------------

Create a bag from a single URL:

```
nabit archive -u https://example.com/ -o example_bag
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

File format
-----------

`bag-nabit` reads and writes a special dialect of [BagIt](https://en.wikipedia.org/wiki/BagIt) designed for attaching provenance to publicly hosted resources.

`nabit`-flavored bags have the following notable features:

* headers.warc records provenance information for files downloaded from the web.
* signatures/ contains a chain of signature files and timestamp files for the tagmanifest.
* standard locations for metadata that is either signed with the bag, or editable after the bag is created.

The layout of a `bag-nabit` bag is as follows:

* `bagit.txt`: standard BagIt file
* `bag-info.txt`: standard BagIt file
* `manifest-sha256.txt`: standard BagIt file
* `tagmanifest-sha256.txt`: standard BagIt file
* `unsigned-metadata.json`: optional, metadata not signed, editable after bag is created
* `data/`
  * `files/`: directory of files added to the bag
    * `...`
  * `headers.warc`: optional, request and response headers from HTTP fetches for files in `files/`
  * `signed-metadata.json`: optional, metadata signed with the bag
* `signatures/`: directory of signature files
  * `tagmanifest-sha256.txt.p7s` -- signature file for `tagmanifest-sha256.txt`
  * `tagmanifest-sha256.txt.p7s.tsr` -- timestamp file for `tagmanifest-sha256.txt.p7s`
  * `tagmanifest-sha256.txt.p7s.tsr.crt` -- certificate file for `tagmanifest-sha256.txt.p7s.tsr`
  * `...` -- other signature files in chain

headers.warc format
+++++++++++++++++++

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

`signatures/` directory format
++++++++++++++++++++++++++++++

The `signatures/` directory contains a chain of signature files and timestamp files for the tagmanifest.

Signing the tagmanifest file is sufficient to ensure the integrity of the bag, as the tagmanifest contains
cryptographic hashes for all tag files, including the manifest file which contains hashes for all data files.

The signatures directory can contain two kinds of attestation files:

* `.p7s` files are PKCS#7 signature files, which assert a domain or email address vouching for the bag contents.
  * `.p7s` files are created with the command `openssl cms -sign -binary -in <original_file> -out <signature_file> -inkey <key_file> -signer <cert_chain> -certfile <cert_chain> -outform PEM`.
  * `.p7s` files can be validated with the command `openssl cms -verify -binary -content <original_file> -in <signature_file> -inform PEM -purpose any`.
* `.tsr` files are timestamp response files, which assert a time before which the bag was created.
  * `.tsr` files are created with the command `openssl ts -query -data <original_file> -no_nonce -sha256 -cert` to generate the request, which is then sent to a timestamping authority.
  * `.tsr` files can be validated with the command `openssl ts -verify -data <original_file> -in <timestamp_file> -CAfile <certificate_file>`.
  * The timestamping authority is expected to be the same one that created the `.tsr.crt` file, which is a copy of the timestamping authority's certificate.
  
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

metadata format
+++++++++++++++

The BagIt specification allows minimal metadata to be stored in the bag-info.txt file,
and any extensive metadata to be stored within the data/ directory.
Headers can be added to bag-info.txt with the `--info / -i` flag to `nabit archive`.

To clarify the distinction between **signed** and **unsigned** metadata, `bag-nabit` extends
this specification to encourage metadata to be stored in two files:

* `data/signed-metadata.json`: metadata signed with the bag.
* `unsigned-metadata.json`: metadata not signed, editable after bag is created.

In practice *any* files within data/ will be signed, and any files outside data/ will not,
but the provided filenames are encouraged to ensure that users will understand the distinction.

Manual bag creation and editing
-------------------------------

After creating a bag, or obtaining a bag from another source, the bag can be edited manually --
for example, by adding files to the data/ directory or editing a metadata file. However, new
data files or edits to signed files will invalidate the signature, causing `nabit validate` to fail.

To re-sign a bag after editing, use the `--amend` flag to `nabit archive`:

```
nabit archive example_bag --amend -s mykey.pem:mychain.pem -t digicert
```

This command will regenerate the manifest files, remove any signatures and timestamps that no
longer validate, and then re-run the signing and timestamping process.

Limitations and Caveats
-----------------------

* Currently only SHA-256 is supported for hashing.
* Currently only PKCS#7 signatures and RFC 3161 timestamps are supported.
* Because empty directories are not included in BagIt manifest files, signatures
  do not verify the presence or absence of empty directories.