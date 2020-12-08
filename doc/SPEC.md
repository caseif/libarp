# Argus Resource Package (ARP) Format Specification

Version 1.0 (Draft)

## 0. Table of Contents

- [0. Table of Contents](#0-table-of-contents)
- [1. Purpose](#1-purpose)
- [2. Definitions](#2-definitions)
- [3. Versioning](#3-versioning)
- [4. File Structure](#4-file-structure)
  - [4.1. Parts](#4.1-parts)
  - [4.2. File Layout](#4.2-file-layout)
  - [4.3. Structures](#4.3-structures)
    - [4.3.1. Header](#4.3.1-header)
    - [4.3.2. Part Header](#4.3.2-part-header)
    - [4.3.3. Catalogue](#4.3.3-catalogue)
      - [4.3.3.1. Node Descriptor](#4.3.3.1-node-descriptor)
    - [4.3.4. Body](#4.3.4-body)
    - [4.3.5. Directory Listing](#4.3.5-directory-listing)
- [5. Magic Values](#5-magic-values)
  - [5.1. Format Magic](#5.1-format-magic)
  - [5.2. Part Magic](#5.2-part-magic)
  - [5.3. Compression Type](#5.3-compression-type)
- [6. Media Types](#6-media-types)
  - [6.1. ARP-Specific Mappings](#6.1-arp-specific-mappings)
- [7. Referencing Resources](#7-referencing-resources)
- [8. External Documentation Referenced](#8-external-documentation-referenced)

## 1. Purpose

The Argus Resource Package (ARP) format is designed to provide a simple, structured format for packaging static assets
in a way which is easily and efficiently parsed.

## 2. Definitions

Strictly speaking, the phrase "ARP package" is tautological. However, for the sake of ease of understanding, this shall
be considered a completely acceptable way of describing a binary structure encoding data in the ARP format, and will be
used to refer to such throughout this specification.

Unless otherwise noted, all string values referred to in the format are stored as null-terminated UTF-8-encoded strings.

Unless otherwise noted, all integer values referred to in the format are encoded as unsigned and little-Endian.

## 3. Versioning

Each version of the ARP specification is identified by a major version and an incremental version). The incremental
version is exclusively used for clarifying, corrective, or otherwise backwards-compatible changes. The format version
specified as a single integer in the header of ARP files corresponds to the major version of the specification that the
file conforms to.

## 4. File Structure

ARP packages are contained by files with the extension `.arp`. The maximum file size is `2^64-1` bytes.

### 4.1. Parts

ARP packages may be split into multiple files (parts) if desired. However, this must be explicitly declared in the
header. A package may have up to 999 parts. The first part has index 1.

Each part file must be named as follows, where `#` represents a digit of the part index: `<package name>.part###.arp`.
For example, part 2 of package foo will be named `foo.part002.arp`. This naming convention is not required for the first
part, which in this case may be named simply `foo.arp`.

Each part must begin with a 16-byte [Part Header](#part-header) (described below). The body section corresponding to the
part immediately follows this header.

### 4.2. File Layout

The first part of an ARP package contains three primary sections: the package header, the directory, and the body. These
sections are described below.

Subsequent parts do not include the package header or directory structures, Instead, they include a shorter
[Part Header](#part-header) followed immediately by the body structure.

### 4.3. Structures

#### 4.3.1. Header

The package header describes the meta-attributes of the ARP package. The structure is described below.

| Offset | Length | Name | Description |
| --: | --: | :-: | :-- |
| `0x0` | `0x8` | Magic | Must be hex sequence `1B` `41` `52` `47` `55` `53` `52` `50` (`0x1B` `ARGUSRP`). |
| `0x8` | `0x2` | Version | The format major version the package conforms to. Parsers should refuse to parse further if they do not provide explicit support for this major version of the format. |
| `0xA` | `0x2` | Compression | The type of compression applied to individual resources in the package as a magic ASCII string. The standard possible values are described in the [Magic Values](#magic-values) section of this document. |
| `0xC` | `0x30` | Namespace | The package namespace as a string. |
| `0x3C` | `0x2` | Parts | The number of files comprising this package. This value must be between 1 and 999, inclusive. |
| `0x3E`| `0x8` | Catalogue Offset | The offset in bytes of the catalogue section, starting from the beginning of the package header. |
| `0x46`| `0x8` | Catalogue Size | The length in bytes of the catalogue section. |
| `0x4E` | `0x3` | Node Count | The number of node descriptors contained by the catalogue. |
| `0x51` | `0x1` | Unused | Unused by this version of the specification. |
| `0x52`| `0x8` | Body Offset | The offset in bytes of the body section of the first part, starting from the beginning of the package header. |
| `0x5A`| `0x8` | Body Size | The length in bytes of the body section. |
| `0x62` | `0x9E` | Reserved | Reserved for future use. |

The package namespace may not contain the characters `/` (forward slash), `\` (back slash), `:` (colon), , nor any
control characters (`U+0000`&ndash;`U+001F`, `U+007F`&ndash;`U+009F`).

#### 4.3.2. Part Header

| Offset | Length | Name | Description |
| --: | --: | :-: | :-- |
| `0x0` | `0x8` | Magic | Must be hex sequence `1B` `41` `52` `47` `55` `53` `50` `54` (`0x1B` `ARGUSPT`). **This is different from the magic in the primary header.** |
| `0x8` | `0x2` | Part Number | The index of this part. This must be between 2 and 999, inclusive. |
| `0xA` | `0x6` | Reserved | Reserved for future use. |

#### 4.3.3. Catalogue

The catalogue structure is comprised of sequential node descriptors which point to directories and resources in the
package. The structure of a node descriptor is described below.

The first node descriptor must describe the root directory of the package. This node has the magic name ""
(empty string).

##### 4.3.3.1. Node Descriptor

A node descriptor describes and points to either a resource or a directory listing within a body section.

Nodes descriptors will contain the CRC-32C checksum of the corresponding data. This may optionally be ignored by the
unpacker if the package specifies a compression scheme which already includes a CRC, such as `bzip2`.

The CRC-32C checksum is to be computed per the IEEE 802.3 standard, with a polynomial of `0x1EDC6F41`.

Nodes descriptors pointing to resources may optionally specify a
[media type](#arp-media-types) describing the type of data contained by
the resource. This may be left empty, in which case compliant parsers will assume a default type
of `application/octet-stream`.

Apart from this, parsers are not required to perform any further validation.

The maximum length by design for each a node name and node media type is 255 bytes.

Node names may not contain the characters `/` (forward slash), `\` (back slash), or `:` (colon), nor any control
characters (`U+0000`&ndash;`U+001F`, `U+007F`&ndash;`U+009F`).

| Offset | Length | Name | Description |
| --: | --: | :-: | :-- |
| `0x0` | `0x2` | Descriptor length | The length of the node descriptor, including this length field. |
| `0x2` | `0x1` | Type | The type of the node. `0` for resource, `1` for directory. |
| `0x3` | `0x2` | Part index | The index of the package part containing the resource data. For directory-type nodes, this must be `1`. |
| `0x5` | `0x8` | Data offset | The offset of this node's data in the body section of the corresponding package part. |
| `0xD` | `0x8` | Data length | The length of the node data in bytes. If this node is a directory, this must be a multiple of 4. |
| `0x15` | `0x8` | Uncompressed data length | The length of the uncompressed node data in bytes. If the package does not use compression or this node is a directory, this field will be ignored. |
| `0x1D` | `0x4` | CRC | The CRC-32C checksum of the node data. |
| `0x21` | `0x1` | Name length | The length of the node name in bytes, not including a null terminator. |
| `0x22` | variable | Name | The name of this node as a string, not including a null terminator. |
| variable | `0x1` | File extension length | The length of the node file extension, if applicable, not including a null terminator. |
| variable | variable | File extension | The extension of the file this node was generated from, if applicable, not including a null terminator.
| variable | `0x1` | Media type length | The length of the node media type in bytes, not including a null terminator. |
| variable | variable | Media type | The media type of this node as an ASCII string, not including a null terminator. |

#### 4.3.4. Body

A body section is comprised of raw resource data. There is no explicit structure in this section. It is organized
according to the directory section.

In the first package part, the corresponding body section begins at the offset defined in the package header. In
subsequent parts, the body immediately follows the header.

#### 4.3.5. Directory Listing

A directory listing describes the contents of a directory. The structure is extremely simple, containing only a
tightly-packed array of 4-byte zero-indexed node descriptor indices.

For example: the data [`0x01` `0x00` `0x00` `0x00` `0x02` `0x00` `0x00` `0x00`] specifies that the directory contains
the nodes with descriptor indices 1 and 2 in the catalogue.

All directory listings must be defined in the first part of the package.

It is illegal for any directory to contain the root directory (index 0) as a child.

## 5. Magic Values

The ARP format makes use of magic values to specify data types in various places. The table below defines the semantic
meaning of each magic byte.

### 5.1. Format Magic

ARP packages must begin with the magic hex sequence `1B` `41` `52` `47` `55` `53` `52` `50` (`0x1B` `ARGUSRP`). Files
not beginning with this magic are not valid ARP packages.

### 5.2. Part Magic

ARP parts following the first must begin with the magic hex sequence `1B` `41` `52` `47` `55` `53` `50` `54` (`0x1B`
`ARGUSPT`). Parts not beginning with this magic should be rejected. **Note that this is not the same as the format
magic.**

### 5.3. Compression Type

Resources in the archive may be compressed with a number of different schemes. The available formats as well as their
magic values are described in the table below.

As of version 1.0, the ARP specification requires that compliant implementations provide support only for the DEFLATE
algorithm. DEFLATE is chosen as the standard compression algorithm for its high compression ratio and decompression
speed.

Generators need not limit themselves to these values if they wish to use other compression schemes, but
decompression support is not guaranteed by the specification.

Only resources may be compressed. Directory listings are always stored uncompressed, irrespective of the package's
compression field.

Compression magic must not contain ASCII control characters.

| Magic | Compression type |
| :-- | :-- |
| `df` | [DEFLATE][1] |

## 6. Media Types

ARP defines a standard format for media type strings as a variant of the syntax defined in section 5.1 of
[RFC 2045][2]. This format differs from the RFC in that the preceding "Content-Type:"
is excluded, and the optional parameter is excluded. As in the standard, ARP media type strings should be present in the
[IANA media types registry][3] unless the format component
is prefixed with `x-`.

The ARP standard references the
[`mime.types`][4] file present in
Apache's `httpd` project as it appears in revision `1884192` for media type mapping. Additionally, Argus defines a
number of other mappings which shall supplement and take precedence over the `mime.types` file.

Additionally, packers should provide a mechanism for user-defined mappings to be used. These shall take precedence over
all other mappings, if applicable, but should typically be used to supplement extensions not covered by the mappings
specified by the ARP standard.

### 6.1. ARP-Specific Mappings

| Extension | Media type |
| :-- | :-- |
| (no extension) | `application/octet-stream` |
| `.lua` | `text/x-lua` |
| `.csh` | `text/x-glsl-comp` |
| `.comp` | `text/x-glsl-comp` |
| `.fsh` | `text/x-glsl-frag` |
| `.frag` | `text/x-glsl-frag` |
| `.geom` | `text/x-glsl-geom` |
| `.tesc` | `text/x-glsl-tess-control` |
| `.tese` | `text/x-glsl-tess-eval` |
| `.vsh` | `text/x-glsl-vert` |
| `.vert` | `text/x-glsl-vert` |

## 7. Referencing Resources

ARP defines an idiomatic way of referencing resources contained by an ARP package via the ARP path specification. An ARP
path contains the following components:

- The namespace of the package containing the resource
- A colon (`:`)
- The parent directories of the resource beginning from the root, with each followed by a forward-slash (`/`)
- The base name of the resource

For example, a package has a namespace of `foo`, a resource in the root called `bar`, and a directory in the root called
`baz`. The `baz` directory contains a resource called `qux`. The path referencing the resource `bar` is `foo:bar`, and
the path referencing the resource `qux` is `foo:baz/qux`.

## 8. External Documentation Referenced

- [IEEE 802.3][1]
- [RFC 1951][2]
- [RFC 2095][3]
- [IANA media types registry][4]
- [httpd: mime.types][5]

[1]: https://standards.ieee.org/standard/802_3-2018.html (IEEE 802.3)
[2]: https://tools.ietf.org/html/rfc1951 (RFC 1951)
[3]: https://tools.ietf.org/html/rfc2045 (RFC 2045)
[4]: https://www.iana.org/assignments/media-types/media-types.xhtml (IANA media types registry)
[5]: https://svn.apache.org/repos/asf/!svn/bc/1884192/httpd/httpd/trunk/docs/conf/mime.types (httpd: mime.types)
