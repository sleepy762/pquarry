# NetScout

A simple network analyzer.

## Building

- Debian/Arch Dependencies (apt/pacman): `cmake`, `make`, `gcc`
- Gentoo Dependencies (emerge): `dev-util/cmake`, `sys-devel/make`, `sys-devel/gcc`
- [libtins](https://github.com/mfontanini/libtins) is another dependency which has to be built and installed. You might have to install it manually because it most likely doesn't exist in your package manager (currently available on the [AUR](https://aur.archlinux.org/packages/libtins/)).

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

Setting pcap filters is optional and they can be left empty. If pcap filters are set then when the sniffer is started it will throw an error if there is a mistake in the filters. If the filters are valid then no error will be thrown and the sniffer will work as expected.

Once an interface has been set, the sniffer can be started by selecting the first option `Start sniffer`. It will print to stdout and save packets to memory according to the filters. Almost every protocol has a unique color to make reading easier. In order to stop the sniffer, a `SIGINT` signal must be sent (Ctrl+C). The sniffer will pause and return to the main menu with all the sniffed packets saved in memory. The sniffer can be resumed by selecting `Start sniffer`.

In order to export saved packets into a pcap file, first make sure that you have started the sniffer and have packets saved. Selecting the option `Export packets into pcap` will bring up a prompt where a name has to be given to the pcap file where the packets will be saved. the `.pcap` file extension is added automatically and there is no need to write it. It is possible to just write a name for the pcap file and it will be saved in the same directory as the NetScout executable. It's also possible to write a full path to anywhere on the machine.

The option `Clear saved packets` can be used to remove all the saved packets.

The option `See information` will print the current interface, filters, and the amount of packets saved.
