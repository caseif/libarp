# Argus Resource Package (ARP) Format Specification

Version 1.0 (Draft)

## Preface

Strictly speaking, the phrase "ARP package" is tautological. However, for the sake of ease of understanding, this shall
be considered a completely acceptable way of describing a binary structure encoding data in the ARP format, and will be
used to refer to such throughout this specification.

Unless otherwise noted, all integer values referred to in the format are to be treated as unsigned and little-Endian.

## Purpose

The Argus Resource Package (ARP) format is designed to provide a simple, structured format for packaging static assets
in a way which is easily and efficiently parsed.

## Versioning

Each version of the ARP specification is identified by a major version and an incremental version). The incremental
version is exclusively used for clarifying, corrective, or otherwise backwards-compatible changes. The format version
specified as a single integer in the header of ARP files corresponds to the major version of the specification that the
file conforms to.

## Container

ARP packages are contained by files with the extension `.arp`. The maximum file size is `2^64-1` bytes.

### Parts

ARP packages may be split into multiple files (parts) if desired. However, this must be explicitly declared in the
header. A package may have up to 99 parts. The first part has index 1.

Each part file must be named as follows: `<package name>.part##.arp`. For example, part 2 of package foo will be named
`foo.part02.arp`. This naming convention is not required for the first part.

Each part must begin with a 16-byte [Part Header](#part-header), which will be ignored in the calculation of
offsets. (For example, if each part is `1000` bytes and the body begins at byte `500`, the data at body offset `600`
will be physically located at byte `116` of the second part).

The main header and directory sections must be contained by the first part.

## Structure

An ARP package contains three primary sections: the header, the directory, and the body. These sections are described
respectively below.

### Header

The package header describes the meta-attributes of the ARP package. The structure is described below

| Offset | Length | Name | Description |
| --: | --: | :-: | :-- |
| `0x0` | `0x8` | Magic | Must be hex sequence `1B` `41` `52` `47` `55` `53` `52` `50` (`0x1B` `ARGUSRP`). |
| `0x8` | `0x2` | Version | The format major version the package conforms to. Parsers should refuse to parse further if they do not provide explicit support for this major version of the format. |
| `0xA` | `0x4` | Header Length | The length of the header in bytes, beginning with the magic number. Useful for slurping the whole header at once if desired. |
| `0xE` | `0x2` | Compression | The type of compression applied to individual resources in the package as a magic ASCII string. The standard possible values are described in the [Magic Values](#magic-values) section of this document. |
| `0x10` | `0x1` | Parts | The number of files comprising this package. This value be between 1 and 99, inclusive. |
| `0x11` | `0x8` | Part Size | The size of each file comprising this package. |
| `0x19` | `0x17` | Reserved | Reserved for future use. |
| `0x30`| `0x8` | Directory Offset | The offset in bytes of the directory section, starting from the beginning of the header. |
| `0x38`| `0x8` | Directory Size | The length in bytes of the directory section. |
| `0x40`| `0x8` | Body Offset | The offset in bytes of the body section, starting from the beginning of the header. This need not be contained by the first part if the package is split across multiple parts. |
| `0x48`| `0x8` | Body Size | The length in bytes of the body section. |

### Part Header

| Offset | Length | Name | Description |
| --: | --: | :-: | :-- |
| `0x0` | `0x8` | Magic | Must be hex sequence `1B` `41` `52` `47` `55` `53` `50` `54` (`0x1B` `ARGUSPT`). **This is different to the magic in the primary header.** |
| `0x8` | `0x1` | Part Number | The index of this part. This must be between 2 and 99. |
| `0x9` | `0x7` | Reserved | Reserved for future use. |

### Directory

The directory begin with an 8-byte length value is comprised of sequential directory entries which point to folders and resources in the package. The
structure of a directory entry is described below.

The first directory entry must describe the root folder of the package. This entry has the magic name `0x00` (a single
`NUL` character).

#### Directory Entry

A directory entry describes and points to either a resource or another directory entry.

Directory entries which point to resource data will contain the CRC-32 of the resource data. This will be ignored if the
package specifies a compression scheme which already includes a CRC, such as `bzip2`.

| Offset | Length | Name | Description |
| --: | --: | :-: | :-- |
| `0x0` | `0x1` | Name Length | The length of the entry name in bytes. |
| `0x1` | `0x1` | Entry Type | The type of the entry. `0` for resource, `1` for directory. |
| `0x2` | `0x8` | Data Pointer | A pointer to this entry's data. This will be an offset into the directory section if the entry is a directory, or into the body section otherwise. See [Parts](#parts) for nuances regarding body section offsets. |
| `0xA` | `0x4` | CRC | The CRC-32 of the entry data if this entry is a resource. If this entry is a directory, this field may be zeroed-out. |
| `0xE` | variable | Entry Name | The name of this entry as a UTF-8-encoded string. |

### Body

The body section is comprised of raw resource data. There is no explicit structure in this section. It is organized
according to the directory section.

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

Generators need not limit themselves to these values if they wish to use other compression schemes, but
parser support may not be guaranteed.

| Magic | Compression Type |
| :-- | :-- |
| `df` | [Deflate](https://en.wikipedia.org/wiki/DEFLATE) |
| `lz` | [LZMA](https://en.wikipedia.org/wiki/Lempel%E2%80%93Ziv%E2%80%93Markov_chain_algorithm) |
| `bz` | [bzip2](https://en.wikipedia.org/wiki/Bzip2) |
