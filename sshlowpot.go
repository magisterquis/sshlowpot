//sshlowpot is a low-interaction ssh honeypot
package main

/*
 * sshlowpot.go
 * Low-interaction honeypot
 * By J. Stuart McMurray
 * Created 20160119
 * Last Modified 20160119
 */

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

var verbon = flag.Bool(
	"v",
	false,
	"Enable verbose logging",
)

func main() {
	var (
		addr = flag.String(
			"a",
			"127.0.0.1:2222",
			"Listen `address`",
		)
		sver = flag.String(
			"ver",
			"SSH-2.0-OpenSSH_7.0",
			"SSH server `version` string",
		)
		privKey = flag.String(
			"key",
			"slp_id_rsa",
			"SSH private key `file`, which will be created if it "+
				"doesn't already exist",
		)
	)
	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			`Usage: %v [options]

Options are:
`,

			os.Args[0],
		)
		flag.PrintDefaults()
	}
	flag.Parse()

	/* High-resolution logging */
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	/* Server Config */
	conf, err := serverConfig(*sver, *privKey)
	if nil != err {
		log.Fatalf("Unable to generate server config: %v", err)
	}

	/* Listen on the address */
	l, err := net.Listen("tcp", *addr)
	if nil != err {
		log.Fatalf("Unable to listen on %v: %v", *addr, err)
	}
	log.Printf("Listening on %v", l.Addr())

	/* Pop off connections, handle them */
	for {
		c, err := l.Accept()
		if nil != err {
			log.Fatalf("Unable to accept new connection: %v", err)
		}
		go handle(c, conf)
	}
}

/* Verbose logging */
func verbose(f string, a ...interface{}) {
	if !*verbon {
		return
	}
	log.Printf(f, a...)
}

/* serverConfig makes an SSH server config struct with server version string
sv and private key from file named pkf. */
func serverConfig(sv, pkf string) (*ssh.ServerConfig, error) {
	/* Config to return */
	c := &ssh.ServerConfig{
		/* Log authentication */
		PasswordCallback:            logPass,
		PublicKeyCallback:           logPubKey,
		KeyboardInteractiveCallback: logKeyInt,

		/* Server Version string */
		ServerVersion: sv,
	}
	/* Try to open the private key file */
	privateKeyFile, err := os.OpenFile(pkf, os.O_RDWR|os.O_CREATE, 0600)
	if nil != err {
		return nil, err
	}
	defer privateKeyFile.Close()

	/* Read the file's contents */
	pkb, err := ioutil.ReadAll(privateKeyFile)
	if nil != err {
		return nil, err
	}
	/* If the file was empty, make a key, write the file */
	if 0 == len(pkb) {
		pkb, err = makeKeyInFile(privateKeyFile)
		if nil != err {
			return nil, err
		}
	} else {
		verbose("Read SSH key file %v", pkf)
	}
	/* Parse the key */
	pk, err := ssh.ParsePrivateKey(pkb)
	if nil != err {
		return nil, err
	}
	/* Add it to the config */
	c.AddHostKey(pk)
	/* Return the config */
	return c, nil
}

/* makeKeyInFile makes a private SSH key and writes it to the file f, and
 * returns what it wrote to the file. */
func makeKeyInFile(f *os.File) ([]byte, error) {
	/* Below code mooched from
	 * http://stackoverflow.com/questions/21151714/go-generate-an-ssh-public-key */
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	/* Encode the key */
	pkb := pem.EncodeToMemory(privateKeyPEM)

	/* Try to write it to the file */
	if _, err := f.Write(pkb); nil != err {
		return nil, err
	}
	verbose("Made SSH key and wrote it to %v", f.Name())

	/* Return the bytes */
	return pkb, nil
}

/* logPass logs a password attempt (and returns failure) */
func logPass(
	conn ssh.ConnMetadata,
	password []byte,
) (*ssh.Permissions, error) {
	log.Printf("%v Password:%q", ci(conn), password)
	return nil, fmt.Errorf("invalid password")
}

/* logPubKey logs a public key attempt */
func logPubKey(
	conn ssh.ConnMetadata,
	key ssh.PublicKey,
) (*ssh.Permissions, error) {
	log.Printf(
		"%v Key(%v):%02X",
		ci(conn),
		key.Type(),
		md5.Sum(key.Marshal()),
	)
	return nil, fmt.Errorf("invalid key")
}

/* logKeyInt logs a keyboard-interactive attempt */
func logKeyInt(
	conn ssh.ConnMetadata,
	client ssh.KeyboardInteractiveChallenge,
) (*ssh.Permissions, error) {
	/* Send a welcome and the prompt */
	a, err := client(
		conn.User(),
		"",
		[]string{"Password: "},
		[]bool{false},
	)
	/* Handle responses */
	if nil != err { /* Something went wrong */
		log.Printf(
			"%v error sending keyboard-interactive prompt: %v",
			ci(conn),
			err,
		)
	} else if 0 == len(a) { /* Didn't get an answer */
		log.Printf("%v no keyboard-interactive answer")
	} else if 1 < len(a) { /* We mysteriously got back too many answers */
		for i, v := range a {
			log.Printf(
				"%v Keyboard-Interactive-%v/%v: %q",
				ci(conn),
				i,
				len(a),
				v,
			)
		}
	} else { /* Got just one answer */
		log.Printf(
			"%v Keyboard-Interactive:%q",
			ci(conn),
			a[0],
		)
	}
	return nil, fmt.Errorf("invalid password")
}

/* ci returns a string containing info from an ssh.ConnMetadata */
func ci(m ssh.ConnMetadata) string {
	return fmt.Sprintf(
		"Address:%v Target:%v Version:%q User:%q",
		m.RemoteAddr(),
		victimName(m),
		m.ClientVersion(),
		m.User(),
	)
}

/* handle handles a new connection */
func handle(c net.Conn, conf *ssh.ServerConfig) {
	verbose("Address:%v Connect", c.RemoteAddr())
	/* Upgrade to an SSH connection */
	sc, _, _, err := ssh.NewServerConn(c, conf)
	if nil != err { /* This should be the norm */
		verbose("Address:%v Disconnect", c.RemoteAddr())
		c.Close()
		return
	}
	defer sc.Close()
	/* If we're here, something funny happened */
	log.Printf("%v authenticated successfully, killing.  This shouldn't happen.", ci(sc))
}

var vn string

/* victimName returns the name of the victim (honeypot) */
func victimName(c ssh.ConnMetadata) string {
	/* Used a cached value */
	if "" != vn {
		return vn
	}
	/* Try the hostname first */
	h, err := os.Hostname()
	if nil != err {
		verbose("Unable to determine hostname: %v", err)
		/* Failing that, use the local address */
		return c.LocalAddr().String()
	}
	vn = h
	return vn
}
