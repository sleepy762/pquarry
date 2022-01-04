# NetScout

A simple network analyzer.

## Building

- Debian/Arch Dependencies (apt/pacman): `cmake`, `make`, `gcc`
- Gentoo Dependencies (emerge): `dev-util/cmake`, `sys-devel/make`, `sys-devel/gcc`
- [libtins](https://github.com/mfontanini/libtins) is another dependency which has to be built and installed. **Make sure to enable C++11 support when compiling libtins.**

Run the following commands in a terminal in the root directory of the project:
```
mkdir build
cd build
cmake ..
make
```
An executable file with the name `NetScout` will be created.

## Running

The executable must be run with root privileges in order to work.

It accepts arguments, both are optional:

- The first argument will fill the `interface` field.
- The second argument and beyond will be concatenated and will fill the `filters` field.
This means that it is possible to run the executable like this, for example:
```
sudo ./NetScout enp3s0 port 443
```
And like this
```
sudo ./NetScout enp3s0 "port 443"
```
Both lines have the same effect.

The arguments are optional. Both the interface and filters can be set and changed in the menu during runtime as well.

## Usage

In order to begin sniffing packets, a valid interface must be set. 

Setting pcap filters is optional and they can be left empty.

Once an interface has been set, the sniffer can be started by selecting the first option `Start sniffer`. If pcap filters were set then the sniffer will throw an error if there is a mistake in the filters. If the filters are valid then no error will be thrown and the sniffer will work as expected. Packets will be printed to stdout and saved in memory according to the filters. Almost every protocol has a unique color to make reading easier. In order to stop the sniffer, a `SIGINT` signal must be sent (Ctrl+C). The sniffer will pause and return to the main menu with all the sniffed packets saved in memory. The sniffer can be resumed by selecting `Start sniffer` again.

In order to export saved packets into a pcap file, first make sure that there are saved packets in memory. Selecting the option `Export packets into pcap` will bring up a prompt where a name has to be given to the pcap file where the packets will be saved. the `.pcap` file extension is added automatically and there is no need to write it. It is possible to just write a name for the pcap file and it will be saved in the same directory as the NetScout executable. It's also possible to write a full path to anywhere on the machine. Leaving the filename empty will abort the export.

The option `Clear saved packets` can be used to remove all the curently saved packets.

The option `See information` will print the current interface, filters, and the amount of packets saved.
