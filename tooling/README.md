# ARP Tooling

This directory contains basic tooling for use in implementing ARP parsers and packers.

## `generate_mt_csv.py`

This script takes multiple inputs and generates a consolidated CSV file containing mappings from file extensions to ARP
media types. The following files are used as input, in descending order of precedence in the resulting file:

| File name | Description | Note |
| :-- | :-- | :-- |
| `user_mappings.csv` | A CSV file provided via the command line mapping file extensions to ARP media types | Each row should contain a single file extension in the first column, and a single ARP media type in the second. |
| `arp_mappings.csv` | A CSV file mappings file extensions to ARP media types | This file's contents are defined by the ARP specification, version 1, [section 6.1][2]. | |
| `mime.types` | httpd's `mime.types` file as directed by the ARP specification, version 1, [section 6][1] | This file is published by Apache into the public domain and thus is not subject to any other license found in this repository. |

The script's output will be written to `output/full_mappings.csv` as a CSV file containing entries consisting of a
single file extension in the first column, and a single ARP media type in the second. Each file extension present in the
file will appear exactly once.

[1]: https://github.com/caseif/libarp/blob/master/doc/SPEC.md#6-media-types
[2]: https://github.com/caseif/libarp/blob/master/doc/SPEC.md#61-arp-specific-mappings
