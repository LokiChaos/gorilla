package main

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"flag"
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

	"github.com/fatih/color"
)

var (
	Validation = 0
)

const (
	// Info messages
	Info = 1 << iota // a == 1 (iota has been reset)

	// Warning Messages
	Warning = 1 << iota // b == 2

	// Error Messages
	Error = 1 << iota // c == 4
)

// Options model for commandline arguments
type Options struct {
	LockFile       string
	DaysExpiration int
	Dirs           []string
	Verbosity      int
}

func main() {

	options := GetOptions()

	havecerts := false
	checkingDirs := options.Dirs

	os.Remove(options.LockFile)

	for _, dir := range checkingDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			printMessage("Directory: "+dir+" does not exist", options.Verbosity, Error)
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

	if Validation > 0 {
		fmt.Println("WARNING - Checked " + strconv.Itoa(Validation) + " cert that need to be updated, please check for more details " + options.LockFile)
		os.Exit(1)
	} else {
		fmt.Println("OK - Checked, all certs are updated.")
		os.Exit(0)
	}
}

func exitCode(err *exec.ExitError) int {
	return err.Sys().(syscall.WaitStatus).ExitStatus()
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

			days := int(c.NotAfter.Sub(time.Now()).Hours() / 24)

			if days > options.DaysExpiration {
				printMessage("Valid cert, skip : "+strings.Join(c.DNSNames, " ")+" - days: "+strconv.Itoa(days), options.Verbosity, Info)
				continue
			} else {
				Validation++
				var dnsvalid = strings.Join(c.DNSNames, " ")
				if len(c.DNSNames) == 0 {
					dnsvalid = "this file " + cert + " haven't DNS field"
				}

				if days < 0 {
					WriteToFile(options.LockFile, "\nDomain: "+dnsvalid+" expired: "+strconv.Itoa(days)+" days ago.\n", options.Verbosity)
				} else {
					WriteToFile(options.LockFile, "\nDomain: "+dnsvalid+" is going to expire in: "+strconv.Itoa(days)+" days.\n", options.Verbosity)
				}

			}

		}

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
func NewOptions(lockfike string, daysexpiration int, dirs string, verbosity int) *Options {
	dirs = strings.Replace(dirs, " ", "", -1)
	dirs = strings.Replace(dirs, " , ", ",", -1)
	dirs = strings.Replace(dirs, ", ", ",", -1)
	dirs = strings.Replace(dirs, " ,", ",", -1)
	dirs_arr := strings.Split(dirs, ",")
	dirs_arr = removeDuplicates(dirs_arr)

	return &Options{
		LockFile:       lockfike,
		DaysExpiration: daysexpiration,
		Dirs:           dirs_arr,
		Verbosity:      verbosity,
	}
}

func GetOptions() *Options {

	var lockfike string
	flag.StringVar(&lockfike, "lockfike", "/etc/certificates.lock", "Lock file location")

	var daysexpiration int
	flag.IntVar(&daysexpiration, "daysexpiration", 15, "Number of days before warning")

	var dirs string
	flag.StringVar(&dirs, "dirs", "/etc/nginx/sites-enabled,/etc/apache2/sites-enabled,/etc/nginx/vhosts.d,/etc/apache2/vhosts.d", "Directories be checked to find certs")

	var verbosity int
	flag.IntVar(&verbosity, "verbosity", 2, "0 = only errors, 1 = important things, 2 = all")

	flag.Parse()

	opts := NewOptions(lockfike, daysexpiration, dirs, verbosity)

	return opts
}

func printMessage(message string, verbosity int, messageType int) {
	colors := map[int]color.Attribute{Info: color.FgGreen, Warning: color.FgHiYellow, Error: color.FgHiRed}

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
