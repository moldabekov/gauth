[![Build Status](https://travis-ci.org/moldabekov/gauth.svg?branch=master)](https://travis-ci.org/moldabekov/gauth)
[![Go Report Card](https://goreportcard.com/badge/github.com/moldabekov/gauth)](https://goreportcard.com/report/github.com/moldabekov/gauth)
## gauth is a two-factor authentication agent.

### Installation:

You have several ways to get `gauth`:

0. Grab `gauth` from [Release page](https://github.com/slmingol/gauth/releases) and place it in your `$PATH`.

1. Please ensure that you set `$GOPATH` and have `$GOPATH/bin` in your `$PATH`. Then run the following command:

	`go install github.com/slmingol/gauth@latest`

2. Install via `brew`:
 
    `brew install slmingol/tap/gauth`

3. Docker:

    `docker pull ghcr.io/slmingol/gauth`
    -or-
    `docker pull slmingol/gauth`

	
### Usage:

	gauth -add [-hotp] name
	gauth -list
	gauth name

To add a new key to keychain use "gauth -add name", where name is a given service name (such as gmail, github and so on).
It'll prompt a 2fa key from stdin. 2fa keys are case-insensitive strings [A-Z2-7].

Default generation algorithm is time based auth codes (TOTP - the same as Google Authenticator).

There is also *EXPERIMENTAL* support of counter based auth codes (HOTP).

To list all entries in the keychain use `gauth -list`

To print certain 2fa auth code use `gauth name`

If no arguments are provided, `gauth` prints all 2fa TOTP auth codes.

**IMPORTANT NOTE:**

TOTP auth codes are derived from key hash and current time. Please ensure that system clock is adjusted via NTP.
Acceptable fault threshold is about ~1 min.

The keychain itself is stored **UNENCRYPTED** in `$HOME/.gauth`.
Take measures to encrypt your partitions (haven't you done this yet?)

### Example

While Google 2fa setup select "enter this text code instead" bypassing QR code scanning. You will get your 2fa secret - short string.

Add it to 2fa under the name google, typing the secret at the prompt:

	$ gauth -add google
	gauth key for google: <secret>

Whenever Google prompts for a 2fa code, run gauth to obtain one:

	$ gauth google
	438163

### Greetings
 - Golang team
 - Russ C.

### Contributing
All PR and Issues are welcome

### License
(C) MIT License
