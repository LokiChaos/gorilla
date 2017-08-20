package main

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	// LockFile saves the domains that needs to be updated
	LockFile = "/etc/certificates.lock"
	// DaysExpiration limit of days before alert
	DaysExpiration = 15
	// Validation is the number of certs to be updated
	Validation = 0
)

func init() {
	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.WarnLevel)
}

func main() {

	havecerts := false
	checkingDirs := []string{"/etc/nginx/sites-enabled", "/etc/apache2/sites-enabled", "/etc/nginx/vhosts.d", "/etc/apache2/vhosts.d"}
	os.Remove(LockFile)

	for _, dir := range checkingDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			log.WithFields(log.Fields{
				"conf": dir,
				"err":  err,
			}).Info("Conf does not exit")
		} else {
			havecerts = true
			list := ListFiles(dir)
			runCheck(list)
		}
	}

	if !havecerts {
		log.WithFields(log.Fields{}).Info("Any cert found.")
		fmt.Println("OK - Any cert found.")
		defer os.Exit(0)
	}

	if Validation > 0 {
		fmt.Println("WARNING - Checked " + strconv.Itoa(Validation) + " cert that need to be updated, please check for more details " + LockFile)
		defer os.Exit(1)
	} else {
		fmt.Println("OK - Checked, all certs are updated.")
		defer os.Exit(0)
	}
}

func exitCode(err *exec.ExitError) int {
	return err.Sys().(syscall.WaitStatus).ExitStatus()
}

func runCheck(domainConfPaths []string) {

	for _, domain := range domainConfPaths {

		if _, err := os.Stat(domain); os.IsNotExist(err) {
			log.WithFields(log.Fields{
				"conf": domain,
				"err":  err,
			}).Info("Conf does not exit")
			continue
		}

		conf, err := certificates(domain)

		if err != nil {
			log.WithFields(log.Fields{
				"conf": domain,
				"err":  err,
			}).Fatal("The ice breaks!")
		}

		for _, cert := range conf {

			c, err := parseCertificate(cert)

			if err != nil {
				if err != nil {
					log.WithFields(log.Fields{
						"conf": domain,
						"err":  err,
					}).Fatal("The ice breaks!")
				}
			}

			days := int(c.NotAfter.Sub(time.Now()).Hours() / 24)

			if days > DaysExpiration {
				log.WithFields(log.Fields{
					"days":           days,
					"DaysExpiration": DaysExpiration,
					"domain":         strings.Join(c.DNSNames, " "),
				}).Info("Valid cert, skip.")
				continue
			} else {
				Validation++
				var dnsvalid = strings.Join(c.DNSNames, " ")
				if len(c.DNSNames) == 0 {
					dnsvalid = "this file " + cert + " haven't DNS field"
				}

				if days < 0 {
					WriteToFile(LockFile, "\nDomain: "+dnsvalid+" expired: "+strconv.Itoa(days)+" days ago.\n")
				} else {
					WriteToFile(LockFile, "\nDomain: "+dnsvalid+" is going to expire in: "+strconv.Itoa(days)+" days.\n")
				}

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
		log.WithFields(log.Fields{
			"Path": rootpath,
			"err":  err,
		}).Warn("walk error")
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
			if _, err := os.Stat(match[2]); !os.IsNotExist(err) {
				r = append(r, match[2])
			}
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
			log.WithFields(log.Fields{
				"filePath": filePath,
				"err":      err,
			}).Warn("Cannot create file")
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
