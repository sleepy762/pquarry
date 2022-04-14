# PacketQuarry

An interactive network analyzer.

## Features
- Capture packets on a local device.
- Capture packets on a remote device.
- See incoming and outgoing packets.
- Export packets into a pcap file.
- Apply filters to the sniffer.

## Dependencies

- Arch (pacman): `cmake` `make` `gcc` `libcap` `openssl`
- Debian (apt): `cmake` `make` `gcc` `libcap-dev` `libssl-dev`
- Gentoo (emerge): `dev-util/cmake` `sys-devel/make` `sys-devel/gcc` `sys-libs/libcap` `dev-libs/openssl`
- [libtins](https://github.com/mfontanini/libtins) is another dependency which has to be built and installed (including its own dependencies). **Make sure to enable C++11 support when compiling libtins.**

## Building and Installing

Run the following commands in a terminal in the root directory of the project:
```
mkdir build
cd build
cmake ..
make
sudo make install
```
Two executables will be created, `pquarry`(client) and `pquarryserver`(server).

A readme file that explains the usage of each executable is available in the respective directory.

To uninstall, run `sudo make uninstall`.
