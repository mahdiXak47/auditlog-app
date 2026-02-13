// One-off utility to generate a bcrypt hash for METRICS_PASSWORD_HASH.
// Usage: echo -n 'your-password' | go run ./cmd/hashpassword/main.go
// Or:   go run ./cmd/hashpassword/main.go 'your-password'
// Put the output in the metrics-auth Secret (key password-hash); never commit the password.
package main

import (
	"fmt"
	"os"
	"io"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	var raw []byte
	if len(os.Args) >= 2 {
		raw = []byte(os.Args[1])
	} else {
		var err error
		raw, err = io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read stdin: %v\n", err)
			os.Exit(1)
		}
	}
	hash, err := bcrypt.GenerateFromPassword(raw, bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bcrypt: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(hash))
}
