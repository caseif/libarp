# libarp

ARP is a binary format for packing resource files in a structured manner. libarp is a reference implementation of
pack/unpack functionality for the format.

ARP's full specification can be found in the [SPEC.md](docs/SPEC.md) file in this repository.

## Compiling

libarp includes optional features (enabled by default) which depend on [zlib](https://www.zlib.net/),
[XZ Utils](https://tukaani.org/xz/), and [bzip2](https://www.sourceware.org/bzip2/). For convenience, these libraries
are provided as git submodules within the repository and will be automatically built alongside the root project. If the
respective features are not enabled, the libraries will not be built.

| Feature flag | Required library | Description |
| :-- | :-- | :-- |
| FEATURE_PACK | N/A | Support for creating ARP packages from loose files |
| FEATURE_UNPACK | N/A | Support for unpacking ARP packages into loose files |
| FEATURE_DEFLATE | zlib | Support for (de)compression using the DEFLATE algorithm |
| FEATURE_LZMA | XZ Utils (`liblzma`) | Support for (de)compression using the LZMA algorithm |
| FEATURE_BZIP2 | bzip2 | Support for (de)compression using the bzip2 algorithm |

To build:

```bash
git submodule update --init
mkdir build
cd build
cmake ..
cmake --build .
```

## License

libarp is made available under the [MIT license](https://opensource.org/licenses/MIT). You may use, modify, and
distribute the project within its terms.
