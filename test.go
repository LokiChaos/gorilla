package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
)

func certificates(filename string) ([]string, error) {
	var r []string
	confSslRegex := regexp.MustCompile("(SSLCertificateFile|ssl_certificate)\\s+([^;]+)\\s*;?\\s*$")

	fh, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer fh.Close()

	scanner := bufio.NewScanner(fh)
	var match []string
	var line string
	for scanner.Scan() {
		line = scanner.Text()
		match = confSslRegex.FindStringSubmatch(line)
		if len(match) == 3 {
			r = append(r, match[2])
		}
	}

	err = scanner.Err()
	if err != nil {
		return nil, err
	}
	return r, nil
}

func main() {
	l, err := certificates(os.Args[1])
	if err != nil {
		panic(err)
	}
	if len(l) == 1 {
		fmt.Printf("found %d certificate:\n", len(l))
	} else if len(l) == 0 {
		fmt.Printf("found %d certificates:\n", len(l))
	} else {
		fmt.Printf("found no certificates\n")
	}
	for _, c := range l {
		fmt.Printf(" - %s\n", c)
	}
}
