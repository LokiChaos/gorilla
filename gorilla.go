package main

import (
	"bufio"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
)

var (
	// Validation number of certs to be updated
	Validation = 0
	// Expired number of certs expired
	Expired = 0

	// Domains all domains to make an extra check before exit
	Domains []string
)

const (
	// Info messages
	Info = 1 << iota // a == 1 (iota has been reset)

	// Warning Messages
	Warning = 1 << iota // b == 2

	// Error Messages
	Error = 1 << iota // c == 4
)

var signatureAlgorithm = [...]string{
	"UnknownSignatureAlgorithm",
	"MD2WithRSA",
	"MD5WithRSA",
	"SHA1WithRSA",
	"SHA256WithRSA",
	"SHA384WithRSA",
	"SHA512WithRSA",
	"DSAWithSHA1",
	"DSAWithSHA256",
	"ECDSAWithSHA1",
	"ECDSAWithSHA256",
	"ECDSAWithSHA384",
	"ECDSAWithSHA512",
}

var publicKeyAlgorithm = [...]string{
	"UnknownPublicKeyAlgorithm",
	"RSA",
	"DAS",
	"ECDSA",
}

// Options model for commandline arguments
type Options struct {
	LockFile       string
	DaysExpiration int
	Dirs           []string
	Letsencrypt    bool
	Verbosity      int
	Cooldown       string
}

type SSLCerts struct {
	SHA1                string
	SubjectKeyId        string
	Version             int
	SignatureAlgorithm  string
	PublicKeyAlgorithm  string
	Subject             string
	DNSNames            []string
	NotBefore, NotAfter string
	ExpiresIn           string
	Issuer              string
	AuthorityKeyId      string
}

func main() {

	options := GetOptions()

	havecerts := false
	checkingDirs := options.Dirs

	os.Remove(options.LockFile)

	for _, dir := range checkingDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			printMessage("Skipping: "+dir, options.Verbosity, Info)
		} else {
			havecerts = true
			list := ListFiles(dir, *options)
			runCheck(list, *options)
		}
	}

	if !havecerts {
		fmt.Println("Any cert found.")
		os.Exit(0)
	}

	if Validation > 0 || Expired > 0 {
		if Expired > 0 {
			fmt.Println("CRITICAL - Checked " + strconv.Itoa(Validation-Expired) + " cert that need to be updated and " + strconv.Itoa(Expired) + " expired certs, please check for more details " + options.LockFile)
			os.Exit(1)
		} else {
			fmt.Println("WARNING - Checked " + strconv.Itoa(Validation) + " cert that need to be updated, please check for more details " + options.LockFile)
			os.Exit(1)
		}
	} else {
		fmt.Println("OK - Checked, all certs are updated.")
		os.Exit(0)
	}
}

func ExpiresIn(t time.Time) string {
	units := [...]struct {
		suffix string
		unit   time.Duration
	}{
		{"days", 24 * time.Hour},
		{"hours", time.Hour},
		{"minutes", time.Minute},
		{"seconds", time.Second},
	}
	d := t.Sub(time.Now())
	for _, u := range units {
		if d > u.unit {
			return fmt.Sprintf("Expires in %d %s", d/u.unit, u.suffix)
		}
	}
	return fmt.Sprintf("Expired on %s", t.Local())
}

func SHA1Hash(data []byte) string {
	h := sha1.New()
	h.Write(data)
	return fmt.Sprintf("%X", h.Sum(nil))
}

func exitCode(err *exec.ExitError) int {
	return err.Sys().(syscall.WaitStatus).ExitStatus()
}

func checkHost(domainName string, skipVerify bool) ([]SSLCerts, error) {

	//Connect network
	ipConn, err := net.DialTimeout("tcp", domainName, 10000*time.Millisecond)
	if err != nil {
		return nil, err
	}
	defer ipConn.Close()

	// Configure tls to look at domainName
	config := tls.Config{ServerName: domainName,
		InsecureSkipVerify: skipVerify}

	// Connect to tls
	conn := tls.Client(ipConn, &config)
	defer conn.Close()

	// Handshake with TLS to get certs
	hsErr := conn.Handshake()
	if hsErr != nil {
		return nil, hsErr
	}

	certs := conn.ConnectionState().PeerCertificates

	if certs == nil || len(certs) < 1 {
		return nil, errors.New("Could not get server's certificate from the TLS connection.")
	}

	sslcerts := make([]SSLCerts, len(certs))

	for i, cert := range certs {
		s := SSLCerts{SHA1: SHA1Hash(cert.Raw), SubjectKeyId: fmt.Sprintf("%X", cert.SubjectKeyId),
			Version: cert.Version, SignatureAlgorithm: signatureAlgorithm[cert.SignatureAlgorithm],
			PublicKeyAlgorithm: publicKeyAlgorithm[cert.PublicKeyAlgorithm],
			Subject:            cert.Subject.CommonName,
			DNSNames:           cert.DNSNames,
			NotBefore:          cert.NotBefore.Local().String(),
			NotAfter:           cert.NotAfter.Local().String(),
			ExpiresIn:          ExpiresIn(cert.NotAfter.Local()),
			Issuer:             cert.Issuer.CommonName,
			AuthorityKeyId:     fmt.Sprintf("%X", cert.AuthorityKeyId),
		}
		sslcerts[i] = s

	}

	return sslcerts, nil
}

func runCheck(domainConfPaths []string, options Options) {

	for _, domain := range domainConfPaths {

		if _, err := os.Stat(domain); os.IsNotExist(err) {
			printMessage("Domain config path: "+domain+" does not exist", options.Verbosity, Error)
			continue
		}

		conf, err := certificates(domain)

		if err != nil {
			printMessage("The ice breaks! "+domain, options.Verbosity, Error)
		}

		for _, cert := range conf {

			c, err := parseCertificate(cert)

			if err != nil {
				if err != nil {
					printMessage("The ice breaks! "+cert, options.Verbosity, Error)
				}
			}
			// Validation if the certificate was issued by LE
			if options.Letsencrypt {
				if !strings.Contains(c.Issuer.CommonName, "Let's Encrypt") {
					printMessage("\nIssuer: "+c.Issuer.CommonName+" not support acme, skip "+domain, options.Verbosity, Error)
					continue
				}
			}

			for _, dom := range c.DNSNames {
				Domains = append(Domains, dom)
			}

			days := int(c.NotAfter.Sub(time.Now()).Hours() / 24)

			if days > options.DaysExpiration {
				printMessage("Valid cert, skip : "+strings.Join(c.DNSNames, " ")+" - days: "+strconv.Itoa(days), options.Verbosity, Info)
				continue
			} else {
				var dnsvalid = strings.Join(c.DNSNames, " ")
				if len(c.DNSNames) == 0 {
					dnsvalid = "this file " + cert + " haven't DNS field"
				}

				Validation++

				if days < 0 {
					Expired++
					printMessage("\nDomain: "+dnsvalid+" expired: "+strconv.Itoa(days)+" days ago.\n", options.Verbosity, Error)
					WriteToFile(options.LockFile, "\nDomain: "+dnsvalid+" expired: "+strconv.Itoa(days)+" days ago.\n", options.Verbosity)
				} else {
					printMessage("\nDomain: "+dnsvalid+" is going to expire in: "+strconv.Itoa(days)+" days.\n", options.Verbosity, Error)
					WriteToFile(options.LockFile, "\nDomain: "+dnsvalid+" is going to expire in: "+strconv.Itoa(days)+" days.\n", options.Verbosity)
				}

			}

		}

	}

	if Validation == 0 && Expired == 0 && checkLockTime(options.Cooldown) {
		// Make this extra check only if the certs are all ok, otherwise not necessary
		printMessage("Running the second check (WEB CHECK) \n", options.Verbosity, Info)

		for _, can := range Domains {
			//var ce string
			var err error
			var certs []SSLCerts
			// Catch any misconfigurations
			certs, err = checkHost(can+":443", true)
			if err != nil {
				Validation++
				printMessage("\nDomain: "+can+":443 can't be verified\n", options.Verbosity, Error)
				WriteToFile(options.LockFile, "\nDomain: "+can+":443 can't be verified, please try telnet "+can+" 443\n", options.Verbosity)
			}
			if len(certs) > 0 {
				exp, _ := strconv.Atoi(certs[0].ExpiresIn)
				if exp > options.DaysExpiration {
					if exp < 0 {
						Expired++
						printMessage("\nDomain: "+can+" expired: "+certs[0].ExpiresIn+" days ago\n", options.Verbosity, Error)
						WriteToFile(options.LockFile, "\nDomain: "+can+" expired: "+certs[0].ExpiresIn+" days ago\n", options.Verbosity)
					} else {
						printMessage("\nDomain: "+can+" is going to expire in: "+certs[0].ExpiresIn+" days.\n", options.Verbosity, Error)
						WriteToFile(options.LockFile, "\nDomain: "+can+" is going to expire in: "+certs[0].ExpiresIn+" days\n", options.Verbosity)
					}
				}
			}
		}
		// Cache this check's values;
		os.Remove(options.Cooldown)
		WriteToFile(options.Cooldown, strconv.Itoa(Expired)+"\n", options.Verbosity)
		WriteToFile(options.Cooldown, strconv.Itoa(Validation)+"\n", options.Verbosity)

	} else {
		// Make this extra check only if the certs are all ok, otherwise not necessary
		printMessage("Skip WEB CHECK \n", options.Verbosity, Info)
		// Skipped check, grab the cached values from the cooldown lock file
		Expired, Validation = getLock(options.Cooldown)
	}
}

// ListFiles give a Array with a list of files in a given path
func ListFiles(rootpath string, options Options) []string {

	list := make([]string, 0, 10)

	err := filepath.Walk(rootpath, func(path string, info os.FileInfo, err error) error {
		if filepath.Ext(info.Name()) == ".conf" {
			list = append(list, path)
		}

		return nil
	})
	if err != nil {
		printMessage("walk error!! "+rootpath, options.Verbosity, Error)
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
func WriteToFile(filePath string, msg string, verbosity int) {

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		_, err := os.Create(filePath)
		if err != nil {
			printMessage("Cannot create the lock file! "+filePath, verbosity, Error)
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

func removeDuplicates(elements []string) []string {
	// Use map to record duplicates as we find them.
	encountered := map[string]bool{}
	result := []string{}

	for v := range elements {
		if encountered[elements[v]] == true {
			// Do not add duplicate.
		} else {
			// Record this element as an encountered element.
			encountered[elements[v]] = true
			// Append to result slice.
			result = append(result, elements[v])
		}
	}
	// Return the new slice.
	return result
}

// difference returns the elements in a that aren't in b
func difference(a, b []string) []string {
	mb := map[string]bool{}
	for _, x := range b {
		mb[x] = true
	}
	ab := []string{}
	for _, x := range a {
		if _, ok := mb[x]; !ok {
			ab = append(ab, x)
		}
	}
	return ab
}

// NewOptions returns a new Options instance.
func NewOptions(lockfike string, daysexpiration int, dirs string, letsencrypt bool, verbosity int, cooldown string) *Options {
	dirs = strings.Replace(dirs, " ", "", -1)
	dirs = strings.Replace(dirs, " , ", ",", -1)
	dirs = strings.Replace(dirs, ", ", ",", -1)
	dirs = strings.Replace(dirs, " ,", ",", -1)
	dirsarr := strings.Split(dirs, ",")
	dirsarr = removeDuplicates(dirsarr)

	return &Options{
		LockFile:       lockfike,
		DaysExpiration: daysexpiration,
		Dirs:           dirsarr,
		Letsencrypt:    letsencrypt,
		Verbosity:      verbosity,
		Cooldown:       cooldown,
	}
}

// GetOptions creates Options type from Commandline arguments
func GetOptions() *Options {

	var lockfike string
	flag.StringVar(&lockfike, "lockfike", "/etc/certificates.lock", "Lock file location")

	var daysexpiration int
	flag.IntVar(&daysexpiration, "daysexpiration", 15, "Number of days before warning")

	var dirs string
	flag.StringVar(&dirs, "dirs", "/etc/nginx/sites-enabled,/etc/apache2/sites-enabled,/etc/nginx/vhosts.d,/etc/apache2/vhosts.d,/etc/apache2/sites.d,/etc/nginx/sites.d", "Directories be checked to find certs")

	var letsencrypt bool
	flag.BoolVar(&letsencrypt, "letsencrypt", true, "Check only if the certificate was issued by letsencrypt")

	var verbosity int
	flag.IntVar(&verbosity, "verbosity", 3, "0 = only errors, 1 = important things, 2 = all, 3 = none")

	var cooldown string
	flag.StringVar(&cooldown, "cooldown", "/tmp/gorilla.lock", "Cooldown file lock location")

	flag.Parse()

	opts := NewOptions(lockfike, daysexpiration, dirs, letsencrypt, verbosity, cooldown)

	return opts
}

func printMessage(message string, verbosity int, messageType int) {
	colors := map[int]color.Attribute{Info: color.FgGreen, Warning: color.FgHiYellow, Error: color.FgRed}

	if verbosity == 2 {
		color.Set(colors[messageType])
		fmt.Println(message)
		color.Unset()
	} else if verbosity == 1 && messageType > 1 {
		color.Set(colors[messageType])
		fmt.Println(message)
		color.Unset()
	} else if verbosity == 0 && messageType > 2 {
		color.Set(colors[messageType])
		fmt.Println(message)
		color.Unset()
	}
}

func checkErr(err error) {
	if err != nil {
		color.Set(color.FgHiRed)
		panic(err)
		color.Unset()
	}
}

// Check if lock file exists and return true it should run check
func checkLockTime(filePath string) bool {
	info, err := os.Stat(filePath)

	if os.IsNotExist(err) {
		return true
	} else if err != nil {
		panic(err)
		return true
	} else if time.Now().Unix()-info.ModTime().Unix() > 3600 {
		return true
	}

	return false
}

func getLock(filePath string) (int, int) {
	file, err := os.Open(filePath)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	line := 0

	ex, va := 0, 0

	for scanner.Scan() {
		if line > 0 {
			ex, err = strconv.Atoi(scanner.Text())
			if err != nil {
				panic(err)
				ex = 10000
			}
		} else {
			va, err = strconv.Atoi(scanner.Text())
			if err != nil {
				panic(err)
				va = 10000
			}
		}
		line++
	}

	return ex, va
}
