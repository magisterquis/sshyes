package main

/*
 * sshyes.go
 * Small SSH server which mostly does not allow users to auth
 * By J. Stuart McMurray
 * Created 20171011
 * Last Modified 20171011
 */

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

func main() {
	var (
		nAuth = flag.Uint(
			"max-tries",
			6,
			"Allow `N` authorization attempts before disconnect",
		)
		sucProb = flag.Uint(
			"suc",
			16,
			"Successful auth `probablity`, as a number "+
				"between 0 and 255", /* Yeah, ugly */
		)
		laddr = flag.String(
			"addr",
			"0.0.0.0:2222",
			"Listen `address`",
		)
		version = flag.String(
			"version",
			"SSH-2.0-OpenSSH_7.6",
			"SSH server `version`",
		)
	)
	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			`Usage: %v [options]

Listens for SSH connections, and rejects them by default.  A certain percentage
will be accepted (and then disconnected).

Options:
`,
			os.Args[0],
		)
		flag.PrintDefaults()
	}
	flag.Parse()

	/* At least one auth attempt must be allowed */
	if 0 == *nAuth {
		log.Fatalf(
			"At least one authentication try (-max-tries) " +
				"must be allowed",
		)
	}

	/* I should probably have done this better */
	if 0 == *sucProb || 255 < *sucProb {
		log.Fatalf(
			"Success probability needs to be between " +
				"1 and 255, inclusive",
		)
	}

	/* Server config */
	prob := byte(*sucProb)
	conf := &ssh.ServerConfig{
		MaxAuthTries: int(*nAuth),
		/* The callbacks all do the same thing under the hood */
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (
			*ssh.Permissions,
			error,
		) {
			return &ssh.Permissions{}, authOk(prob)
		},
		PublicKeyCallback: func(
			conn ssh.ConnMetadata,
			key ssh.PublicKey,
		) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, authOk(prob)
		},
		KeyboardInteractiveCallback: func(
			conn ssh.ConnMetadata,
			client ssh.KeyboardInteractiveChallenge,
		) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, authOk(prob)
		},
		/* Log auth attempts */
		AuthLogCallback: func(
			conn ssh.ConnMetadata,
			method string,
			err error,
		) {
			ok := "FAIL"
			if nil == err {
				ok = "SUCCESS"
			}
			log.Printf(
				"[%v] %v %q (%v): %v",
				conn.RemoteAddr(),
				method,
				conn.ClientVersion(),
				conn.User(),
				ok,
			)
		},
		ServerVersion: *version,
	}
	/* Add keys to the config */
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Unable to generate SSH key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if nil != err {
		log.Fatalf("Unable to parse SSH key: %v", err)
	}
	log.Printf(
		"SSH key fingerprint (MD5): %v",
		ssh.FingerprintLegacyMD5(signer.PublicKey()),
	)
	log.Printf(
		"SSH key fingerprint (SHA256): %v",
		ssh.FingerprintSHA256(signer.PublicKey()),
	)
	conf.AddHostKey(signer)

	/* Listen for connections */
	l, err := net.Listen("tcp", *laddr)
	if nil != err {
		log.Fatalf("Unable to listen on %q: %v", *laddr, err)
	}
	log.Printf("Listening on %v for SSH connections", l.Addr())

	/* Handle them */
	for {
		c, err := l.Accept()
		if nil != err {
			log.Printf("Unable to accept connection: %v", err)
			time.Sleep(time.Minute)
			continue
		}
		go handle(c, conf)
	}
}

/* handle performs an SSH handshake with c, using the config conf. */
func handle(c net.Conn, conf *ssh.ServerConfig) {
	defer c.Close()
	defer log.Printf("[%v] Disconnected", c.RemoteAddr())
	log.Printf("[%v] Connected", c.RemoteAddr())
	_, _, _, _ = ssh.NewServerConn(c, conf)
}

/* authOk returns nil if the auth is allowed, based on sucProb */
func authOk(sucProb byte) error {
	/* Get a random number */
	b := make([]byte, 1)
	if _, err := rand.Read(b); nil != err {
		return fmt.Errorf("random read: %v", err)
	}
	/* See if it's a winner */
	if b[0] <= sucProb {
		return nil
	}
	return errors.New("permission denied")
}
