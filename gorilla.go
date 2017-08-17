package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const dirPath = "/tmp/"

var (
	confSslRegex = regexp.MustCompile(`(root|ssl_certificate|ssl_certificate_key|ssl_session_ticket_key|ssl_dhparam|ssl_trusted_certificate)\s+([a-z0-9_\-\.\/]+?);`)
)

type ngxCertificate struct {
	privkey   string
	fullchain string
}

type ngxSiteConf struct {
	Certificates          []ngxCertificate
	SslSessionTicketKey   string
	SslDHParam            string
	SslTrustedCertificate string
	DomainPublicDir       string
}

func main() {

	list := ListFiles("/home/mauro/Downloads/SSL")
	runCheck(list)
}

func runCheck(domainConfPaths []string) {

	for _, domain := range domainConfPaths {

		if _, err := os.Stat(domain); os.IsNotExist(err) {
			logf("%s conf: %v", domain, err)
			continue
		}

		conf, err := parseSiteConf(domain)

		if err != nil {
			fatalf("%s conf: %v", domain, err)
		}

		for _, cert := range conf.Certificates {

			c, err := parseCertificate(cert.fullchain)

			if err != nil {
				fatalf("%s cert: %v", domain, err)
			}

			days := int(c.NotAfter.Sub(time.Now()).Hours() / 24)

			if days > 15 {
				logf("%s %d days valid, skip.", filepath.Base(cert.fullchain), days)
				continue
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

func parseSiteConf(confFilename string) (*ngxSiteConf, error) {
	text, err := ioutil.ReadFile(confFilename)

	if err != nil {
		return nil, err
	}

	matches := confSslRegex.FindAllStringSubmatch(string(text), -1)

	var conf = &ngxSiteConf{}
	var cert *ngxCertificate

	for _, match := range matches {

		if len(match) == 3 {
			key, value := match[1], match[2]

			switch key {
			case "ssl_certificate":
				if cert == nil {
					cert = &ngxCertificate{
						fullchain: value,
					}
				} else {
					cert.fullchain = value
					conf.Certificates = append(conf.Certificates, *cert)
					cert = nil
				}
			case "ssl_certificate_key":
				if cert == nil {
					cert = &ngxCertificate{
						privkey: value,
					}
				} else {
					cert.privkey = value
					conf.Certificates = append(conf.Certificates, *cert)
					cert = nil
				}
			case "ssl_session_ticket_key":
				conf.SslSessionTicketKey = value
			case "ssl_dhparam":
				conf.SslDHParam = value
			case "ssl_trusted_certificate":
				conf.SslTrustedCertificate = value
			case "root":
				if conf.DomainPublicDir == "" {
					conf.DomainPublicDir = value
				}
			}
		}

	}
	return conf, nil
}

var logf = log.Printf

func errorf(format string, args ...interface{}) {
	logf(format, args...)
}

func fatalf(format string, args ...interface{}) {
	errorf(format, args...)
}
