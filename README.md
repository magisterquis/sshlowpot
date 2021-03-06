# sshlowpot
Yet another no-frills low-interaction ssh honeypot in Go.

Accepts SSH connections on a given port (2222 by default), records
authentication attempts and tells the connecting client the authentication
failed.

**Please note that this is not yet production code.  In particular, the log
output is subject to change.**

## Installation
Get and build the source:
```bash
go get github.com/magisterquis/sshlowpot
go install github.com/magisterquis/sshlowpot
```
Compiled binaries can be made available upon request.

Make sure IP forwarding is enabled and forward the port.  The following
examples assume the external-facing port is 22 and sshlowpot is listening on
2222.

OpenBSD:
```bash
#Assuming the external-facing interface is vio0

[root@box]# sysctl net.inet.ip.forwarding=1
[root@box]# echo "pass in on vio0 from any to (vio0) port 22 rdr-to 127.0.0.1 port 2222" >> /etc/pf.conf
[root@box]# pfctl -vf /etc/pf.conf
[user@box]$ sshlowopt -v
```

Linux:
```bash
[root@box]# sysctl net.ipv4.ip_forward=1
[root@box]# iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 22 -j REDIRECT --to-port 2222
[user@box]$ sshlowpot -v
```
 
## Usage
```
Usage: sshlowpot [options]

Options are:
  -a address
    	Listen address (default "127.0.0.1:2222")
  -key file
    	SSH private key file, which will be created if it doesn't already exist (default "slp_id_rsa")
  -to timeout
    	SSH handshake timeout (default 1m0s)
  -v	Enable verbose logging
  -ver version
    	SSH server version string (default "SSH-2.0-OpenSSH_7.0")
```

For the most part, no options are required as long as you can forward your
external port of choice to 127.0.0.1:2222.  Please don't run it as root on 22.

## Output
Output should look something like the following (with `-v`):
```
2016/01/19 19:43:41 Made SSH key and wrote it to slp_id_rsa
2016/01/19 19:43:41 Listening on 127.0.0.1:2222
2016/01/19 19:43:51 Address:168.235.89.22:52119 Connect
2016/01/19 19:43:53 Address:168.235.89.22:52119 User:"exuser" Version:"SSH-2.0-OpenSSH_7.0" Key(ssh-rsa):BE9DA2A4D129652DB64AF6D71DEFD25F
2016/01/19 19:43:56 Address:168.235.89.22:52119 User:"exuser" Version:"SSH-2.0-OpenSSH_7.0" Keyboard-Interactive:"passtry1"
2016/01/19 19:43:57 Address:168.235.89.22:52119 User:"exuser" Version:"SSH-2.0-OpenSSH_7.0" Keyboard-Interactive:"passtry2"
2016/01/19 19:43:58 Address:168.235.89.22:52119 User:"exuser" Version:"SSH-2.0-OpenSSH_7.0" Keyboard-Interactive:"passtry3"
2016/01/19 19:43:59 Address:168.235.89.22:52119 User:"exuser" Version:"SSH-2.0-OpenSSH_7.0" Password:"passtry4"
2016/01/19 19:44:01 Address:168.235.89.22:52119 User:"exuser" Version:"SSH-2.0-OpenSSH_7.0" Password:"passtry5"
2016/01/19 19:44:02 Address:168.235.89.22:52119 User:"exuser" Version:"SSH-2.0-OpenSSH_7.0" Password:"passtry6"
2016/01/19 19:44:02 Address:168.235.89.22:52119 Disconnect
```

## Windows
It should run on Windows just fine.  If it doesn't, feel free to send a pull
request.
