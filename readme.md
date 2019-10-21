# Compile

    $ git clone https://github.com/anton-veretenenko/insys-sniff
    $ cd insys-sniff/
    $ git clone https://github.com/zserge/jsmn
    $ make

# Run

Supply parameters in command line, -d for network device, -f for a single filter. You may also add multiple filters.
Examples

    $ sudo ./insys-sniff -d eth0 -f u,8.8.8.8,53 -f u,77.88.8.8,53
Use zero address as port only filtering.

    $ sudo ./insys-sniff -d eth0 -f u,0.0.0.0,53
Or use zero port for ip only filtering.

    $ sudo ./insys-sniff -d eth0 -f u,8.8.8.8,0
Use 'u' for udp, 't' for tcp protocols filtering, also you may use numbers for protocols.
ICMP filter for example.

    $ sudo ./insys-sniff -d eth0 -f 1,8.8.8.8,0
IPv6 supported.

    $ sudo ./insys-sniff -d eth0 -f 58,2a00:1450:400f:808::200e,0

If no command line parameters supplied, app will try to get config from config.json file.

Expected output:
SourceIP:Port  DestIP:Port  Protocol   Size

    $ sudo ./insys-sniff -d eth0 -f 58,2a00:1450:400f:808::200e,0
    Filter 58,2a00:1450:400f:808::200e,0
    2002:2ea3:9cd9:0:1827:13c4:c3fc:a7eb:0   2a00:1450:400f:808::200e:0      58      118 b
    2002:2ea3:9cd9:0:1827:13c4:c3fc:a7eb:0   2a00:1450:400f:808::200e:0      58      118 b
    2002:2ea3:9cd9:0:1827:13c4:c3fc:a7eb:0   2a00:1450:400f:808::200e:0      58      118 b
Or

    $ sudo ./insys-sniff -d eth0 -f u,8.8.8.8,53
    Filter u,8.8.8.8,53
    192.168.77.137:47784     8.8.8.8:53      17      51 b
    8.8.8.8:53       192.168.77.137:47784    17      67 b
    192.168.77.137:57693     8.8.8.8:53      17      51 b
    8.8.8.8:53       192.168.77.137:57693    17      79 b


# Shutdown
Use Ctrl+C to terminate.
