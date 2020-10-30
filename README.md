# libarp

ARP is a binary format for packing resource files in a structured manner. libarp is a reference implementation of
pack/unpack functionality for the format.

ARP's full specification can be found in the [SPEC.md](doc/SPEC.md) file in this repository.

## Compiling

libarp depends on [zlib](https://www.zlib.net/) for DEFLATE (de)compression support. This library is provided as a Git
submodule within this repository and will be automatically built alongside the root project.

To build:

```bash
git submodule update --init
mkdir build
cd build
cmake ..
cmake --build .
```

## License

libarp is made available under the [MIT License](https://opensource.org/licenses/MIT). You may use, modify, and
distribute the project within its terms.

The ARP specification is made available under the
[Apache License, Version 2.0](https://opensource.org/licenses/Apache-2.0). You may use, modify and redistribute the
specification within its terms.
