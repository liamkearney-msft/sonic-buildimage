HOWTO Use Virtual Switch (Docker)

MACsec-enabled cSONiC neighbours
------------------------------

`docker-sonic-vs` includes `macsecmgrd`, `wpa_supplicant`, and the MACsec
config/show/clear plugins. These run directly in the flat container; there is
no nested `macsec` service container. `macsecmgrd` starts after `start.sh`
completes through supervisord's dependent-startup listener.

Build the Bookworm container after configuring the VS platform:

```
make configure PLATFORM=vs
BLDENV=bookworm make -f Makefile.work SONIC_IMAGE_VERSION=<version> target/docker-sonic-vs.gz
```

The runtime host must provide the Linux MACsec driver, the cipher capabilities
required by the selected profile, and `/dev/net/tun`. The privileged runtime
below shares the host kernel; the container does not supply a separate kernel.
Use isolated network namespaces and synthetic fixture keys for tests. Raw MACsec
status and diagnostic logs can contain key material and must not be published.

Inside the container, check `supervisorctl status macsecmgrd` and use the native
`config macsec`, `show macsec`, and `sonic-clear macsec` commands. Configure the
same test profile on both endpoints and bring the bound ports administratively
up. Successful process startup alone does not establish MKA or encrypted
forwarding. Software MACsec tests do not validate physical ASIC offload or
chassis-fabric behaviour.


1. Create a docker with two front panel ports

```
$ docker run -id --name sw debian bash
$ sudo ./create_vnet.sh -n 2 sw
$ ip netns list
sw-srv1 (id: 6)
sw-srv0 (id: 5)
```

2. Start sonic virtual switch docker

```
$ docker run --privileged --network container:sw --name vs -d docker-sonic-vs
```

3. Setup IP in the virtual switch docker

```
$ docker exec -it vs bash
root@2e9b5c2dc2a2:/# config interface ip add Ethernet0 10.0.0.0/31
root@2e9b5c2dc2a2:/# config interface ip add Ethernet4 10.0.0.2/31
root@2e9b5c2dc2a2:/# config interface startup Ethernet0
root@2e9b5c2dc2a2:/# config interface startup Ethernet4
```

4. Setup IP in the server network namespace

```
$ sudo ip netns exec sw-srv0 ifconfig eth0 10.0.0.1/31
$ sudo ip netns exec sw-srv0 ip route add default via 10.0.0.0
$ sudo ip netns exec sw-srv1 ifconfig eth0 10.0.0.3/31
$ sudo ip netns exec sw-srv1 ip route add default via 10.0.0.2
```

5. Ping from sw-srv0 to sw-srv1

```
$ sudo ip netns exec sw-srv0 ping  10.0.0.3
PING 10.0.0.3 (10.0.0.3) 56(84) bytes of data.
64 bytes from 10.0.0.3: icmp_seq=1 ttl=63 time=0.137 ms
64 bytes from 10.0.0.3: icmp_seq=2 ttl=63 time=0.148 ms
64 bytes from 10.0.0.3: icmp_seq=3 ttl=63 time=0.149 ms
```
