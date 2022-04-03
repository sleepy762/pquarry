# NetScout Client

## Running

The client accepts arguments, both are optional:

- The first argument will fill the `interface` field.
- The second argument and beyond will be concatenated and will fill the `filters` field.
This means that it is possible to run the executable like this, for example:
```
NetScout enp3s0 port 443
```
And like this
```
NetScout enp3s0 "port 443"
```
Both lines have the same effect (`enp3s0` is the interface and `port 443` is the filter).

Both the interface and filters can be set and changed in the menu during runtime.

## Usage

#### Local Sniffing

In order to begin capturing packets, a valid interface must be set. The program will list the available interfaces for your convenience.

Setting pcap filters is optional and they can be left empty.

Once an interface has been set, the sniffer can be started by selecting the first option `Start sniffer`. The sniffer will check the validity of the pcap filters if they were set. If the filters are valid then the sniffer will work as expected. If the pcap filters are invalid, the sniffer will throw an error. Packets will be printed to stdout and saved in memory according to the filters. Almost every protocol has a unique color to make reading easier (Uses ANSI color codes). In order to stop the sniffer, a `SIGINT` signal must be sent (Ctrl+C). The sniffer will pause and return to the main menu with all the captured packets saved in memory. The sniffer can be resumed by selecting `Start sniffer` again.

In order to export saved packets into a pcap file, first make sure that there are saved packets in memory. Selecting the option `Export packets into pcap` will bring up a prompt where a name has to be given to the pcap file where the packets will be saved. the `.pcap` file extension is added automatically and there is no need to write it. It is possible to just write a name for the pcap file and it will be saved in the directory where NetScout was run from. It's also possible to write a full path to anywhere on the machine. Leaving the filename empty will abort the export.

The option `Clear saved packets` can be used to remove all the curently saved packets.

The option `See information` will print the current interface, filters, and the amount of packets saved.

#### Remote Sniffing

The client allows capturing packets on a remote machine. The remote machine must run the `NetScoutServer` executable in order for the client to connect to it.

Once the IP address and port are entered, the client will connect with the server and the server will send a list of the available interfaces. The client must select one valid interface. Afterwards the client will be asked to set filters, which are optional.

After configuring the remote sniffer, it will start sending packets to the client. The packets will be printed to stdout and saved in the memory so they can be exported.
