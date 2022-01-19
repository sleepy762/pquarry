# NetScout Server

## Running

The executable must be run as root in order to work (root permissions are reduced during runtime).

The server requires a port argument, for example:
```
sudo ./NetScoutServer 1337
```
This line will launch the server on the port 1337.

Once the server is started, clients will be able to connect to it. The server will print the address and port of every client that connects to it. It will also print a message when a client disconnects.

**NOTE:** There is a hardcoded filter in the server sniffer that filters out traffic on the port that the server and client communicate in.
