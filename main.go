// gauth is a two-factor authentication agent.
//
// Usage:
//
//	gauth -add [-7] [-8] [-hotp] name
//	gauth -list
//	gauth name
//
// To add a new key to keychain use "gauth -add name", where name is a given name.
// It'll prompt a 2fa key from stdin
// 2fa keys are case-insensitive strings [A-Z2-7].
//
// Default generation algorithm is time based auth codes
// (TOTP - the same as Google Authenticator)
//
// There is also EXPERIMENTAL support of counter based auth codes (HOTP).
//
//
// To list all names in the keychain use "gauth -list"
//
// To print certain 2fa auth code use "gauth name"
//
// If no arguments are provided, gauth prints all 2fa TOTP auth codes.
//
// IMPORTANT NOTE:
// TOTP auth codes are derived from key hash and current time.
// Please ensure that system clock are adjusted via NTP.
// Acceptable fault threshold is about ~1 min.
//
// The keychain itself is stored UNENCRYPTED in $HOME/.gauth.
// Take measures to encrypt your partitions (haven't you done this yet?)
//
// Example
//
// While Google 2fa setup select "enter this text code instead"
// bypassing QR code scanning. You will get your 2fa secret - short string.
//
// Add it to 2fa under the name google, typing the secret at the prompt:
//
//	$ gauth -add google
//	gauth key for google: <secret>
//	$
//
// Whenever Google prompts for a 2fa code, run gauth to obtain one:
//
//	$ gauth google
//	438163
//

package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Keychain is a file format storage.
type Keychain struct {
	file string
	data []byte
	keys map[string]Key
}

// Key describes `keys` in Keychain
type Key struct {
	raw    []byte
	digits int // length
	offset int // counter offset
}

const counterLen = 20

var (
	flagAdd  = flag.Bool("add", false, "add a key")
	flagList = flag.Bool("list", false, "list keys")
	flagHotp = flag.Bool("hotp", false, "add key as HOTP (counter-based) key")
)

func help() {
	fmt.Println(os.Args[0])
	fmt.Fprintf(os.Stderr, "usage:\n")
	fmt.Fprintf(os.Stderr, "\t%s -add [-hotp] keyname\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\t%s -list\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\t%s keyname\n", os.Args[0])
	os.Exit(1)
}

// Read line by line into memory
// handling key length and validity
func readKeychain(file string) *Keychain {
	c := &Keychain{
		file: file,
		keys: make(map[string]Key),
	}
	data, err := ioutil.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			return c
		}
		log.Fatal(err)
	}
	c.data = data

	lines := bytes.SplitAfter(data, []byte("\n"))
	offset := 0
	for i, line := range lines {
		lineno := i + 1
		offset += len(line)
		f := bytes.Split(bytes.TrimSuffix(line, []byte("\n")), []byte(" "))
		if len(f) == 1 && len(f[0]) == 0 {
			continue
		}
		if len(f) >= 3 && len(f[1]) == 1 && '6' <= f[1][0] && f[1][0] <= '8' {
			var k Key
			name := string(f[0])
			k.digits = int(f[1][0] - '0')
			raw, err := decodeKey(string(f[2]))
			if err == nil {
				k.raw = raw
				if len(f) == 3 {
					c.keys[name] = k
					continue
				}
				if len(f) == 4 && len(f[3]) == counterLen {
					_, err := strconv.ParseUint(string(f[3]), 10, 64)
					// even in case of err handle counter and pass it further
					if err == nil {
						k.offset = offset - counterLen
						if line[len(line)-1] == '\n' {
							k.offset--
						}
						c.keys[name] = k
						continue
					}
				}
			}
		}
		log.Printf("%s:%d: invalid key", c.file, lineno)
	}
	return c
}

// dump 2fa list
func (c *Keychain) list() {
	var names []string
	for name := range c.keys {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Println(name)
	}
}

func checkSpace(r rune) rune {
	if unicode.IsSpace(r) {
		return -1
	}
	return r
}

// handle flag conflicts and verify key validity
func (c *Keychain) add(name string) {
	size := 6
	fmt.Fprintf(os.Stderr, "gauth key for %s: ", name)
	text, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		log.Fatalf("error reading key: %v", err)
	}
	text = strings.Map(checkSpace, text)
	if _, err := decodeKey(text); err != nil {
		log.Fatalf("invalid key: %v", err)
	}

	line := fmt.Sprintf("%s %d %s", name, size, text)
	if *flagHotp {
		line += " " + strings.Repeat("0", 20)
	}
	line += "\n"

	f, err := os.OpenFile(c.file, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		log.Fatalf("opening keychain: %v", err)
	}
	// vital
	f.Chmod(0600)

	if _, err := f.Write([]byte(line)); err != nil {
		log.Fatalf("adding key: %v", err)
	}
	if err := f.Close(); err != nil {
		log.Fatalf("closing keychain while adding key: %v", err)
	}
}

func (c *Keychain) code(name string) string {
	k, ok := c.keys[name]
	if !ok {
		log.Fatalf("no such key %q", name)
	}
	var code int
	if k.offset != 0 {
		n, err := strconv.ParseUint(string(c.data[k.offset:k.offset+counterLen]), 10, 64)
		if err != nil {
			log.Fatalf("invalid key counter for %q (%q)", name, c.data[k.offset:k.offset+counterLen])
		}
		n++
		code = genHOTP(k.raw, n, k.digits)
		f, err := os.OpenFile(c.file, os.O_RDWR, 0600)
		if err != nil {
			log.Fatalf("opening keychain: %v", err)
		}
		if _, err := f.WriteAt([]byte(fmt.Sprintf("%0*d", counterLen, n)), int64(k.offset)); err != nil {
			log.Fatalf("updating keychain: %v", err)
		}
		if err := f.Close(); err != nil {
			log.Fatalf("closing keychain while updating keychain: %v", err)
		}
	} else {
		// Time-based key.
		code = genTOTP(k.raw, time.Now(), k.digits)
	}
	return fmt.Sprintf("%0*d", k.digits, code)
}

func (c *Keychain) print(name string) {
	fmt.Printf("%s\n", c.code(name))
}

func (c *Keychain) printAll() {
	var names []string
	max := 0
	maxDigits := 0
	for name, k := range c.keys {
		names = append(names, name)
		if max < len(name) {
			max = len(name)
		}
		if max < k.digits {
			max = k.digits
		}
	}
	sort.Strings(names)
	for _, name := range names {
		k := c.keys[name]
		code := strings.Repeat("-", k.digits)
		if k.offset == 0 {
			code = c.code(name)
		}
		fmt.Printf("%-*s\t%s\n", maxDigits, code, name)
	}
}

func decodeKey(key string) ([]byte, error) {
	return base32.StdEncoding.DecodeString(strings.ToUpper(key))
}

func genTOTP(key []byte, t time.Time, digits int) int {
	return genHOTP(key, uint64(t.UnixNano())/30e9, digits)
}

func genHOTP(key []byte, counter uint64, digits int) int {
	h := hmac.New(sha1.New, key)
	binary.Write(h, binary.BigEndian, counter)
	sum := h.Sum(nil)
	v := binary.BigEndian.Uint32(sum[sum[len(sum)-1]&0x0F:]) & 0x7FFFFFFF
	d := uint32(1)
	for i := 0; i < digits && i < 8; i++ {
		d *= 10
	}
	return int(v % d)
}

func main() {
	log.SetPrefix("gauth: ")
	log.SetFlags(0)
	flag.Usage = help
	flag.Parse()

	k := readKeychain(filepath.Join(os.Getenv("HOME"), ".gauth"))

	if *flagList {
		if flag.NArg() != 0 {
			help()
		}
		k.list()
		return
	}
	if flag.NArg() == 0 && !*flagAdd {
		k.printAll()
		return
	}
	if flag.NArg() != 1 {
		help()
	}
	name := flag.Arg(0)
	if strings.IndexFunc(name, unicode.IsSpace) >= 0 {
		log.Fatal("spaces aren't allowed")
	}
	if *flagAdd {
		k.add(name)
		return
	}
	k.print(name)
}
