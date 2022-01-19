# NetScout

A simple network analyzer.

## Building

- Arch Dependencies (pacman): `cmake`, `make`, `gcc`, `libcap`
- Debian Dependencies (apt): `cmake`, `make`, `gcc`, `libcap-dev`
- Gentoo Dependencies (emerge): `dev-util/cmake`, `sys-devel/make`, `sys-devel/gcc`, `sys-libs/libcap`
- [libtins](https://github.com/mfontanini/libtins) is another dependency which has to be built and installed (including its own dependencies). **Make sure to enable C++11 support when compiling libtins.**

Run the following commands in a terminal in the root directory of the project:
```
mkdir build
cd build
cmake ..
make
```
Two executables will be created, `NetScout`(client) and `NetScoutServer`(server).

A readme file that explains the usage of each executable is available in the respective directory.
