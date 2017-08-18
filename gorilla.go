package main

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

// LockFile location
var LockFile = "/etc/certificates.lock"

//DaysExpiration limit of days before alert
var DaysExpiration = 15

var logf = log.Printf

var validation = 0

func main() {

	havecerts := false
	checkingDirs := []string{"/etc/nginx/sites-enabled", "/etc/apache2/sites-enabled", "/etc/nginx/vhosts.d", "/etc/apache2/vhosts.d"}

	for _, dir := range checkingDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			//logf("%s conf: %v", dir, err)
		} else {
			havecerts = true
			list := ListFiles(dir)
			runCheck(list)
		}
	}

	if !havecerts {
		os.Exit(0)
	}

	if validation > 0 {
		println("WARNING - " + strconv.Itoa(validation) + " certs need to be updated, please check: " + LockFile)
		os.Exit(1)
	} else {
		println("OK - All certs are updated.")
		os.Exit(0)
	}
}

func runCheck(domainConfPaths []string) {

	for _, domain := range domainConfPaths {

		if _, err := os.Stat(domain); os.IsNotExist(err) {
			logf("%s conf: %v", domain, err)
			continue
		}

		conf, err := certificates(domain)

		if err != nil {
			fatalf("%s conf: %v", domain, err)
		}

		for _, cert := range conf {

			c, err := parseCertificate(cert)

			if err != nil {
				fatalf("%s cert: %v", domain, err)
			}

			days := int(c.NotAfter.Sub(time.Now()).Hours() / 24)

			if days > DaysExpiration {
				//logf("%s %d days valid, skip.", filepath.Base(cert), days)
				continue
			} else {
				validation++
				WriteToFile(LockFile, "\nDomain: "+filepath.Base(cert)+" is going to expire in: "+strconv.Itoa(days)+" days.\n")
			}

		}

	}

}

// ListFiles give a Array with a list of files in a given path
func ListFiles(rootpath string) []string {

	list := make([]string, 0, 10)

	err := filepath.Walk(rootpath, func(path string, info os.FileInfo, err error) error {
		if filepath.Ext(info.Name()) == ".conf" {
			list = append(list, path)
		}

		return nil
	})
	if err != nil {
		fmt.Printf("walk error [%v]\n", err)
	}
	return list
}

func parseCertificate(path string) (*x509.Certificate, error) {

	bytes, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(bytes)

	cert, err := x509.ParseCertificate(block.Bytes)

	if err != nil {
		return nil, err
	}

	return cert, nil
}

func certificates(filename string) ([]string, error) {
	var r []string
	confSslRegex := regexp.MustCompile("^/(!#)(SSLCertificateFile|ssl_certificate)\\s+([^;]+)\\s*;?\\s*$")

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

// WriteToFile create a file and writes a specified msg to it
func WriteToFile(filePath string, msg string) {

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		_, err := os.Create(filePath)
		if err != nil {
			log.Fatal("Cannot create file", err)
		}
	}

	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}

	defer file.Close()

	if _, err = file.WriteString(msg); err != nil {
		panic(err)
	}

}

func errorf(format string, args ...interface{}) {
	logf(format, args...)
}

func fatalf(format string, args ...interface{}) {
	errorf(format, args...)
}
