package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/n-yarvex/kami-core/config"
	"github.com/n-yarvex/kami-core/core"
	_ "github.com/n-yarvex/kami-core/include"
	"github.com/n-yarvex/kami-core/klog"
	"github.com/n-yarvex/kami-core/tlsx"
)

const usage = `kami - small multi-protocol proxy kernel

usage:
  kami run   -c config.json     run the proxy (SIGHUP reloads)
  kami check -c config.json     validate a configuration and exit
  kami gen uuid                 print a random UUID
  kami gen key [bytes]          print a random base64 key (default 32 bytes)
  kami gen cert -d dir host...  write a self-signed pair and print its pin
  kami version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = run(os.Args[2:])
	case "check":
		err = check(os.Args[2:])
	case "gen":
		err = gen(os.Args[2:])
	case "version":
		fmt.Println("kami", core.Version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "kami:", err)
		os.Exit(1)
	}
}

func confPath(name string, args []string) (string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	path := fs.String("c", "config.json", "configuration file")
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	return *path, nil
}

func run(args []string) error {
	path, err := confPath("run", args)
	if err != nil {
		return err
	}
	return core.NewManager(path).Run()
}

func check(args []string) error {
	path, err := confPath("check", args)
	if err != nil {
		return err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	in, err := core.New(cfg, klog.Discard())
	if err != nil {
		return err
	}
	in.Close()
	fmt.Println("configuration ok")
	return nil
}

func gen(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("gen what? uuid, key or cert")
	}
	switch args[0] {
	case "uuid":
		var b [16]byte
		rand.Read(b[:])
		b[6] = b[6]&0x0f | 0x40
		b[8] = b[8]&0x3f | 0x80
		h := hex.EncodeToString(b[:])
		fmt.Printf("%s-%s-%s-%s-%s\n", h[:8], h[8:12], h[12:16], h[16:20], h[20:])
	case "key":
		n := 32
		if len(args) > 1 {
			v, err := strconv.Atoi(args[1])
			if err != nil || v < 1 || v > 1024 {
				return fmt.Errorf("key size must be between 1 and 1024")
			}
			n = v
		}
		b := make([]byte, n)
		rand.Read(b)
		fmt.Println(base64.StdEncoding.EncodeToString(b))
	case "cert":
		fs := flag.NewFlagSet("gen cert", flag.ContinueOnError)
		dir := fs.String("d", ".", "output directory")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			return fmt.Errorf("give at least one host name or IP")
		}
		c, k, pin, err := tlsx.WritePair(*dir, fs.Args()...)
		if err != nil {
			return err
		}
		fmt.Printf("cert: %s\nkey:  %s\npin:  %s\n", c, k, pin)
	default:
		return fmt.Errorf("unknown gen target %q", args[0])
	}
	return nil
}
