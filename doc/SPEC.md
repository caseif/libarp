# Argus Resource Package (ARP) Format Specification

Version 1.0 (Draft)

## Preface

Strictly speaking, the phrase "ARP package" is tautological. However, for the sake of ease of understanding, this shall
be considered a completely acceptable way of describing a binary structure encoding data in the ARP format, and will be
used to refer to such throughout this specification.

Unless otherwise noted, all string values referred to in the format are stored as null-terminated UTF-8-encoded strings.

Unless otherwise noted, all integer values referred to in the format are encoded as unsigned and little-Endian.

## Purpose

The Argus Resource Package (ARP) format is designed to provide a simple, structured format for packaging static assets
in a way which is easily and efficiently parsed.

## Versioning

Each version of the ARP specification is identified by a major version and an incremental version). The incremental
version is exclusively used for clarifying, corrective, or otherwise backwards-compatible changes. The format version
specified as a single integer in the header of ARP files corresponds to the major version of the specification that the
file conforms to.

## File Structure

ARP packages are contained by files with the extension `.arp`. The maximum file size is `2^64-1` bytes.

### Parts

ARP packages may be split into multiple files (parts) if desired. However, this must be explicitly declared in the
header. A package may have up to 999 parts. The first part has index 1.

Each part file must be named as follows, where `#` represents a digit of the part index: `<package name>.part###.arp`.
For example, part 2 of package foo will be named `foo.part002.arp`. This naming convention is not required for the first
part, which in this case may be named simply `foo.arp`.

Each part must begin with a 16-byte [Part Header](#part-header) (described below). The body section corresponding to the
part immediately follows this header.

### File Layout

The first part of an ARP package contains three primary sections: the package header, the directory, and the body. These
sections are described below.

Subsequent parts do not include the package header or directory structures, Instead, they include a shorter
[Part Header](#part-header) followed immediately by the body structure.

### Structures

#### Header

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

#### Part Header

| Offset | Length | Name | Description |
| --: | --: | :-: | :-- |
| `0x0` | `0x8` | Magic | Must be hex sequence `1B` `41` `52` `47` `55` `53` `50` `54` (`0x1B` `ARGUSPT`). **This is different from the magic in the primary header.** |
| `0x8` | `0x2` | Part Number | The index of this part. This must be between 2 and 999, inclusive. |
| `0xA` | `0x6` | Reserved | Reserved for future use. |

#### Catalogue

The catalogue structure is comprised of sequential node descriptors which point to directories and resources in the
package. The structure of a node descriptor is described below.

The first node descriptor must describe the root directory of the package. This node has the magic name ""
(empty string).

##### Node Descriptor

A node descriptor describes and points to either a resource or a directory listing within a body section.

Nodes descriptors will contain the CRC-32 of the corresponding data. This may optionally be ignored by the unpacker if
the package specifies a compression scheme which already includes a CRC, such as `bzip2`.

The maximum length for an node name by design is 255 bytes.

Node names may not contain the characters `/` (forward slash), `\` (back slash), or `:` (colon), nor any control
characters (`U+0000`&ndash;`U+001F`, `U+007F`&ndash;`U+009F`).

| Offset | Length | Name | Description |
| --: | --: | :-: | :-- |
| `0x0` | `0x1` | Name Length | The length of the node name in bytes, not including a null terminator. |
| `0x1` | `0x1` | Node Type | The type of the node. `0` for resource, `1` for directory. |
| `0x2` | `0x2` | Part index | The index of the package part containing the resource data. For directory-type nodes, this must be `1`. |
| `0x4` | `0x8` | Data offset | The offset of this node's data in the body section of the corresponding package part. |
| `0xC` | `0x8` | Data Length | The length of the node data in bytes. If this node is a directory, this must be a multiple of 4. |
| `0x14` | `0x4` | CRC | The CRC-32 of the node data. |
| `0x18` | variable | Node Name | The name of this node as a string, not including a null terminator. |

#### Body

A body section is comprised of raw resource data. There is no explicit structure in this section. It is organized
according to the directory section.

In the first package part, the corresponding body section begins at the offset defined in the package header. In
subsequent parts, the body immediately follows the header.

#### Directory Listing

A directory listing describes the contents of a directory. The structure is extremely simple, containing only a
tightly-packed array of 4-byte zero-indexed node descriptor indices.

For example: the data [`0x01` `0x00` `0x00` `0x00` `0x02` `0x00` `0x00` `0x00`] specifies that the directory contains
the nodes with descriptor indices 1 and 2 in the catalogue.

All directory listings must be defined in the first part of the package.

It is illegal for any directory to contain the root directory (index 0) as a child.

## Magic Values

The ARP format makes use of magic values to specify data types in various places. The table below defines the semantic
meaning of each magic byte.

### Format Magic

ARP packages must begin with the magic hex sequence `1B` `41` `52` `47` `55` `53` `52` `50` (`0x1B` `ARGUSRP`). Files
not beginning with this magic are not valid ARP packages.

### Part Magic

ARP parts following the first must begin with the magic hex sequence `1B` `41` `52` `47` `55` `53` `50` `54` (`0x1B`
`ARGUSPT`). Parts not beginning with this magic should be rejected. **Note that this is not the same as the format
magic.**

### Compression Type

Files in the archive may be compressed with a number of different schemes. The available formats as well as their
magic values are described in the table below.

As of version 1.0, the ARP specification requires that compliant implementations provide support only for the DEFLATE
algorithm. DEFLATE is chosen as the standard compression algorithm for its high compression ratio and decompression
speed.

Generators need not limit themselves to these values if they wish to use other compression schemes, but
decompression support is not guaranteed by the specification.

Compression magic must not contain ASCII control characters.

| Magic | Compression Type |
| :-- | :-- |
| `df` | [DEFLATE](https://en.wikipedia.org/wiki/Lempel%E2%80%93Ziv%E2%80%93Markov_chain_algorithm) |

## Referencing Resources

ARP defines an idiomatic way of referencing resources contained by an ARP package via the ARP path specification. An ARP
path contains the following components:

- The namespace of the package containing the resource
- A colon (`:`)
- The parent directories of the resource beginning from the root, with each followed by a forward-slash (`/`)
- The base name of the resource

For example, a package has a namespace of `foo`, a resource in the root called `bar`, and a directory in the root called
`baz`. The `baz` directory contains a resource called `qux`. The path referencing the resource `bar` is `foo:bar`, and
the path referencing the resource `qux` is `foo:baz/qux`.
