# Argus Resource Package (ARP) Format Specification

Version 1.0 (Draft)

## Table of Contents

- [Table of Contents](#table-of-contents)
- [0. Foreword](#0-foreword)
- [1. Purpose](#1-purpose)
- [2. Definitions](#2-definitions)
- [3. Versioning](#3-versioning)
- [4. File Structure](#4-file-structure)
  - [4.1. Parts](#41-parts)
  - [4.2. File Layout](#42-file-layout)
  - [4.3. Structures](#43-structures)
    - [4.3.1. Header](#431-header)
    - [4.3.2. Part Header](#432-part-header)
    - [4.3.3. Catalogue](#433-catalogue)
      - [4.3.3.1. Node Descriptor](#4331-node-descriptor)
    - [4.3.4. Body](#434-body)
    - [4.3.5. Directory Listing](#435-directory-listing)
- [5. Magic Values](#5-magic-values)
  - [5.1. Format Magic](#51-format-magic)
  - [5.2. Part Magic](#52-part-magic)
  - [5.3. Compression Type](#53-compression-type)
- [6. Media Types](#6-media-types)
  - [6.1. ARP-Specific Mappings](#61-arp-specific-mappings)
- [7. Referencing Resources](#7-referencing-resources)
- [8. External Documentation Referenced](#8-external-documentation-referenced)

## 0. Foreword

This is a DRAFT specification and is subject to change without notice and in ways which are not backwards-compatible
with previous draft revisions. Once the initial specification is finalized with version 1.0, further revisions will be
properly versioned.

## 1. Purpose

The Argus Resource Package (ARP) format is designed to provide a simple, structured format for packaging static assets
in a way which is easily and efficiently parsed.

## 2. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in [RFC 2119][4].

Strictly speaking, the phrase "ARP package" is tautological. However, for the sake of ease of understanding, this SHALL
be considered an acceptable way of describing a binary structure encoding data in the ARP format, and will be used to
refer to such throughout this specification.

Unless otherwise noted, all STRING values referred to in the format SHALL be stored and interpreted as null-terminated
UTF-8-encoded strings.

Unless otherwise noted, all INTEGER values referred to in the format SHALL be encoded and interpreted as unsigned and
little-Endian.

## 3. Versioning

Each version of the ARP specification is identified by a major version and an incremental version). The incremental
version SHALL be exclusively used for clarifying, corrective, or otherwise backwards-compatible changes. The format
version specified as a single INTEGER in the header of ARP files SHALL correspond to the major version of the
specification that the file conforms to.

## 4. File Structure

ARP packages SHOULD be contained by files with the extension `.arp`. ARP packages SHALL have a maximum size of `2^64-1`
bytes.

### 4.1. Parts

ARP packages MAY be split into multiple files (parts) if desired. However, this MUST be explicitly declared in the
header. A package MAY have up to 999 parts. The first part MUST have index 1.

Each part file MUST be named as follows, where `#` represents a digit of the part index: `<package name>.part###.arp`.
For example, part 2 of package foo SHALL be named `foo.part002.arp`. This naming convention is OPTIONAL for the first
part, which in this case MAY be named simply `foo.arp`.

Each part MUST begin with a 16-byte [Part Header](#432-part-header) (described below). The body section corresponding to
the part MUST immediately follow this header.

### 4.2. File Layout

The first part of an ARP package SHALL contain three primary sections: the package header, the directory, and the body.
These sections are described below. Note that the body section of the first part, while technically REQUIRED, MAY have a
length of 0 bytes and is thus effectively OPTIONAL.

Subsequent parts SHALL NOT include the package header or directory structures, Instead, they SHALL include a shorter
[Part Header](#432-part-header) followed immediately by the body structure.

### 4.3. Structures

#### 4.3.1. Header

The package header describes the meta-attributes of the ARP package. The structure is described below.

| Offset | Length | Type | Name | Description |
| --: | --: | :-: | :-: | :-- |
| `0x0` | `0x8` | byte sequence | Magic | MUST be hex sequence `1B` `41` `52` `47` `55` `53` `52` `50` (`0x1B` `ARGUSRP`). |
| `0x8` | `0x2` | INTEGER | Version | The format major version the package conforms to. Parsers MUST refuse to parse further if they do not provide explicit support for this major version of the format. |
| `0xA` | `0x2` | ASCII string | Compression | The type of compression applied to individual resources in the package as a magic ASCII string. The standard possible values are described in the [Magic Values](#5-magic-values) section of this document. |
| `0xC` | `0x30` | STRING | Namespace | The package namespace as a STRING. |
| `0x3C` | `0x2` | INTEGER | Parts | The number of files comprising this package. This value MUST be between 1 and 999, inclusive. |
| `0x3E`| `0x8` | INTEGER | Catalogue Offset | The offset in bytes of the catalogue section, starting from the beginning of the package header. |
| `0x46`| `0x8` | INTEGER | Catalogue Size | The length in bytes of the catalogue section. |
| `0x4E` | `0x4` | INTEGER | Node Count | The number of node descriptors contained by the catalogue. |
| `0x52` | `0x4` | INTEGER | Directory Count | The number of directories contained by the catalogue. |
| `0x56` | `0x4` | INTEGER | Resource Count | The number of resources contained by the catalogue. |
| `0x5A`| `0x8` | INTEGER | Body Offset | The offset in bytes of the body section of the first part, starting from the beginning of the package header. |
| `0x62`| `0x8` | INTEGER | Body Size | The length in bytes of the body section of the first part. |
| `0x6A` | `0x96` | (none) | Reserved | Reserved for future use. |

The package namespace is constrained as described in [Section 7](#7-resource-identifiers).

#### 4.3.2. Part Header

| Offset | Length | Type | Name | Description |
| --: | --: | :-: | :-: | :-- |
| `0x0` | `0x8` | byte sequence | Magic | MUST be hex sequence `1B` `41` `52` `47` `55` `53` `50` `54` (`0x1B` `ARGUSPT`). **This is different from the magic in the primary header.** |
| `0x8` | `0x2` | INTEGER | Part Number | The index of this part. This MUST be between 2 and 999, inclusive. |
| `0xA` | `0x6` | (none) | Reserved | Reserved for future use. |

#### 4.3.3. Catalogue

The catalogue structure is comprised of sequential node descriptors which point to directories and resources in the
package. The structure of a node descriptor is described below.

The first node descriptor MUST describe the root directory of the package. This node has the magic name "" (empty
string).

##### 4.3.3.1. Node Descriptor

A node descriptor describes and points to either a resource or a directory listing within a body section.

Nodes descriptors MUST contain the CRC-32C checksum of the corresponding data. This MAY be ignored by the unpacker if
the package specifies a compression scheme which already includes a CRC, such as `bzip2`.

The CRC-32C checksum SHALL be computed per the IEEE 802.3 standard, with a polynomial of `0x1EDC6F41`.

Nodes descriptors pointing to resources MAY specify a [media type](#6-media-types) describing the type of data contained
by the resource. This MAY be left empty, in which case parsers SHALL assume a default type of
`application/octet-stream`.

Apart from validating the checksum, any further validation by parsers against the node data is strictly OPTIONAL.

Node name nor media types SHALL NOT exceed 255 bytes in length.

Node names MUST NOT contain any reserved characters as defined by [Section 7](#7-resource-identifiers).

| Offset | Length | Type | Name | Description |
| --: | --: | :-: | :-: | :-- |
| `0x0` | `0x2` | INTEGER | Descriptor length | The length of the node descriptor, including this length field. |
| `0x2` | `0x1` | INTEGER | Type | The type of the node. `0` for resource, `1` for directory. |
| `0x3` | `0x2` | INTEGER | Part index | The index of the package part containing the resource data. For directory-type nodes, this MUST be `1`. |
| `0x5` | `0x8` | INTEGER | Data offset | The offset of this node's data in the body section of the corresponding package part. |
| `0xD` | `0x8` | INTEGER | Packed data length | The length of the packed node data in bytes. If this node is a directory, this MUST be a multiple of 4. |
| `0x15` | `0x8` | INTEGER | Unpacked data length | The length of the unpacked node data in bytes. If the package uses compression, this MAY be different from the packed length. |
| `0x1D` | `0x4` | INTEGER | CRC | The CRC-32C checksum of the node data. |
| `0x21` | `0x1` | INTEGER | Name length | The length of the node name in bytes, not including a null terminator. |
| `0x22` | `0x1` | INTEGER | File extension length | The length of the node file extension, if applicable, not including a null terminator. |
| `0x23` | `0x1` | INTEGER | Media type length | The length of the node media type in bytes, not including a null terminator. |
| `0x24` | variable | STRING | Name | The name of this node as a STRING, not including a null terminator. |
| variable | variable | STRING | File extension | The extension of the file this node was generated from, if applicable, not including a null terminator.
| variable | variable | ASCII string | Media type | The media type of this node as an ASCII string, not including a null terminator. |

#### 4.3.4. Body

A body section is comprised of raw resource data. There is no explicit structure in this section. It SHALL be organized
according to the directory section.

In the first package part, the corresponding body section SHALL begin at the offset defined in the package header. In
subsequent parts, the body MUST immediately follow the header.

#### 4.3.5. Directory Listing

A directory listing describes the contents of a directory. The structure is extremely simple, containing only a
tightly-packed array of 4-byte zero-indexed node descriptor indices.

For example: the data [`0x01` `0x00` `0x00` `0x00` `0x02` `0x00` `0x00` `0x00`] specifies that the directory contains
the nodes with descriptor indices 1 and 2 in the catalogue.

All directory listings MUST be defined in the first part of the package.

A directory MUST NOT contain the root directory (index 0) as a child.

A package SHOULD NOT contain any set of directories which include one another in a cyclical manner, including the case
of a directory containing itself.

## 5. Magic Values

The ARP format makes use of magic values to specify data types in various places. The table below defines the semantic
meaning of each magic byte.

### 5.1. Format Magic

ARP packages MUST begin with the magic hex sequence `1B` `41` `52` `47` `55` `53` `52` `50` (`0x1B` `ARGUSRP`). Files
not beginning with this magic are MUST NOT be considered valid ARP packages.

### 5.2. Part Magic

ARP parts following the first MUST begin with the magic hex sequence `1B` `41` `52` `47` `55` `53` `50` `54` (`0x1B`
`ARGUSPT`). Parts not beginning with this magic SHALL be rejected.

**Note that this is not the same as the format magic.**

### 5.3. Compression Type

Resources in the archive MAY be compressed with a number of different schemes. The available formats as well as their
magic values are described in the table below.

As of version 1.0, compliant implementations MUST provide support for the DEFLATE algorithm. DEFLATE is chosen as the
standard compression algorithm for its high compression ratio and decompression speed.

Generators MAY use other compression schemes, but decompression support is not guaranteed by the specification.

Only resources MAY be compressed. Directory listings SHALL always be stored uncompressed, irrespective of the package's
compression field.

Compression magic MUST NOT contain ASCII control characters.

| Magic | Compression type |
| :-- | :-- |
| `df` | [DEFLATE][2] |

## 6. Media Types

ARP defines a standard format for media type strings as a variant of the syntax defined in section 5.1 of [RFC 2045][3].
This format differs from the RFC in that the preceding "Content-Type:" is excluded, and the optional parameter is
excluded. As in the standard, ARP media type strings MUST be present in the [IANA media types registry][4] unless the
format component is prefixed with `x-`.

ARP media types strings SHALL be encoded and interpreted as ASCII strings.

The ARP specification references the [`mime.types`][5] file present in Apache's `httpd` project as it appears in
revision `1884192` for media type mapping. Additionally, the ARP specification MAY define other mappings which
SHALL take precedence over the `mime.types` file. These supplementary mappings are listed below.

Packers SHOULD provide a mechanism for user-defined mappings to be used. These SHALL take precedence over all other
mappings, if applicable, but SHOULD typically be used to supplementally map extensions not included in the mappings
specified by the ARP standard.

### 6.1. ARP-Specific Mappings

| Extension | Media type |
| :-- | :-- |
| (no extension) | `application/octet-stream` |

## 7. Resource Identifiers

ARP defines an idiomatic way of referencing resources contained by an ARP package via the ARP identifier specification.

Note that while similar in appearance, ARP identifiers are **not** URIs. The URI specification requires a scheme, which
is not provided for by the ARP identifier specification. ARP identifiers instead begin with a namespace, which is
**not** semantically interchangable.

For the purposes of ARP identifiers and their componenents, the characters `/`, `\`, and `:` SHALL be considered
reserved. The set of characters including all reserved characters along with control characters (including
`U+0000`&ndash;`U+001F` and `U+007F`&ndash;`U+009F`) SHALL be considered illegal. All characters not in the set of
illegal characters SHALL be considered legal.

An ARP identifier is defined by the following ABNF rules (as specified by [RFC 5234][4]):

```abnf
ARP-identifier  = namespace ":" path

namespace       = 1*( idchar )

path            = path-part *( "/" path-part )

path-part       = 1*( idchar )

idchar          = ALPHA / DIGIT / symchar / cschar

symchar         = %x20-2E / %x3C-40 / %x5B / %x5D-60 / %x7B-7E

cschar          = %xA0-D7FF / %xF900-FDCF / %xFDF0-FFEF
                / %x10000-1FFFD / %x20000-2FFFD / %x30000-3FFFD
                / %x40000-4FFFD / %x50000-5FFFD / %x60000-6FFFD
                / %x70000-7FFFD / %x80000-8FFFD / %x90000-9FFFD
                / %xA0000-AFFFD / %xB0000-BFFFD / %xC0000-CFFFD
                / %xD0000-DFFFD / %xE1000-EFFFD
```

Additionally, the first character of a namespace SHOULD be a letter as defined by the Unicode specification. The ARP
specification does not restrict usage to any given version of [the Unicode specification][8].

As an example, a package has a namespace of `foo`, a resource in the root called `bar`, and a directory in the root
called `baz`. The `baz` directory contains a resource called `qux`. The path referencing the resource `bar` is
`foo:bar`, and the path referencing the resource `qux` is `foo:baz/qux`.

## 8. External Documentation Referenced

- [IEEE 802.3][1]
- [RFC 1951][2]
- [RFC 2045][3]
- [RFC 2119][4]
- [RFC 5234][5]
- [IANA media types registry][6]
- [httpd: mime.types][7]
- [Unicode][8]

[1]: https://standards.ieee.org/standard/802_3-2018.html (IEEE 802.3)
[2]: https://tools.ietf.org/html/rfc1951 (RFC 1951)
[3]: https://tools.ietf.org/html/rfc2045 (RFC 2045)
[4]: https://tools.ietf.org/html/rfc2119 (RFC 2119)
[5]: https://tools.ietf.org/html/rfc5234 (RFC 5234)
[6]: https://www.iana.org/assignments/media-types/media-types.xhtml (IANA media types registry)
[7]: https://svn.apache.org/repos/asf/!svn/bc/1884192/httpd/httpd/trunk/docs/conf/mime.types (httpd: mime.types)
[8]: https://www.unicode.org/versions/ (Unicode)
