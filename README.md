# sshlowpot
Yet another no-frills low-interaction ssh honeypot in Go.

Accepts SSH connections on a given port (2222 by default), records
authentication attempts and tells the connecting client the authentication
failed.

## Installation
Get and build the source:
```bash
go get github.com/kd5pbo/sshlowpot
go install github.com/kd5pbo/sshlowpot
```
Compiled binaries can be made available upon request.

Make sure IP forwarding is enabled and forward the port.  The following
examples assume the external-facing port is 22 and sshlowpot is listening on
2222.

OpenBSD:
```bash
Assuming the external-facing interface is vio0

# sysctl net.inet.ip.forwarding=1
# echo "pass in on vio0 from any to (vio0) port 22 rdr-to 127.0.0.1 port 2222 >> /etc/pf.conf
# pfctl -vf /etc/pf.conf
$ sshlowopt -v
```

Linux:
```bash
# sysctl net.ipv4.ip_forward=1
# iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 22 -j REDIRECT --to-port 2222
$ sshlowpot -v
```
 
## Usage
```bash
Usage: sshlowpot [options]

Options are:
  -a string
    	Listen address (default "127.0.0.1:2222")
  -key string
    	SSH private key file, which will be created if it doesn't already exist (default "id_rsa")
  -v	Enable verbose logging
  -ver string
    	SSH server version string (default "SSH-2.0-OpenSSH_7.0")
```

For the most part, no options are required as long as you can forward your
external port of choice to 127.0.0.1:2222.  Please don't run it as root on 22.

## Output
Output should look something like the following (with -v):
```
2016/01/19 19:43:41 Made SSH key and wrote it to id_rsa
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
