package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
)

func index(slice []string, value string) int {
	for i := range slice {
		if value == slice[i] {
			return i
		}
	}
	return -1
}

func contains(slice []string, value string) bool {
	if i := index(slice, value); i != -1 {
		return true
	}
	return false
}

func tryCommand(desc string, command string, args []string) {
	log.Print(desc)
	cmd := exec.Command(command, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("%s failed with error \"%s\" and output: %s", desc, err, string(out))
	}
}

// TODO Generate cert with missing SAN
// TODO Generate cert with invalid extended key usage
// TODO Generate cert with invalid CN
// TODO Generate cert with invalid CA signature
func generate() {
	tryCommand("Generate private key for CA", "openssl", []string{"genrsa", "-out", "mongodb-ca.key", "4096"})
	tryCommand(
		"Request X.509 certificate for CA",
		"openssl",
		[]string{
			"req",
			"-new",
			"-x509",
			"-days", "1826",
			"-key", "mongodb-ca.key",
			"-out", "mongodb-ca.crt",
			"-config", "openssl-ca.conf",
			"-subj", "/C=DE/ST=Baden-Wuerttemberg/L=Karlsruhe/O=MongoDB/OU=Professional Services/CN=CA",
		},
	)
	tryCommand("Copy to PEM file", "cp", []string{"mongodb-ca.crt", "mongodb-ca.pem"})

	opensslServerConfBase, err := os.ReadFile("openssl-server.conf")
	if err != nil {
		log.Fatal(err)
	}

	for _, v := range []int{1, 2, 3} {
		// Generate configuration
		f, err := os.OpenFile(fmt.Sprintf("openssl-server%d.conf", v), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		if _, err = f.Write(opensslServerConfBase); err != nil {
			log.Fatal(err)
		}
		if _, err = fmt.Fprintln(f, fmt.Sprintf("DNS.1 = server%d.mongodb.com", v)); err != nil {
			log.Fatal(err)
		}
		if _, err = fmt.Fprintln(f, fmt.Sprintf("DNS.2 = server%d", v)); err != nil {
			log.Fatal(err)
		}
		if _, err = fmt.Fprintln(f, fmt.Sprintf("DNS.3 = 192.168.0.%d", v)); err != nil {
			log.Fatal(err)
		}
		if err = f.Close(); err != nil {
			log.Fatal(err)
		}

		// Create server certificate
		tryCommand(
			fmt.Sprintf("Generate private key for server %d", v),
			"openssl",
			[]string{"genrsa", "-out", fmt.Sprintf("mongodb-server%d.mongodb.com.key", v), "4096"},
		)
		tryCommand(
			fmt.Sprintf("Generate certificate signing request for server %d", v),
			"openssl",
			[]string{
				"req",
				"-new",
				"-key", fmt.Sprintf("mongodb-server%d.mongodb.com.key", v),
				"-out", fmt.Sprintf("mongodb-server%d.mongodb.com.csr", v),
				"-config", fmt.Sprintf("openssl-server%d.conf", v),
				"-subj", fmt.Sprintf("/C=DE/ST=Baden-Wuerttemberg/L=Karlsruhe/O=MongoDB/OU=Professional Services/CN=mongodb-server%d.mongodb.com", v),
			},
		)
		tryCommand(
			fmt.Sprintf("Generate X.509 certificate for server %d", v),
			"openssl",
			[]string{
				"x509",
				"-req",
				"-days", "365",
				"-in", fmt.Sprintf("mongodb-server%d.mongodb.com.csr", v),
				"-CA", "mongodb-ca.crt",
				"-CAkey", "mongodb-ca.key",
				"-CAcreateserial",
				"-out", fmt.Sprintf("mongodb-server%d.mongodb.com.crt", v),
				"-extfile", fmt.Sprintf("openssl-server%d.conf", v),
				"-extensions", "v3_req",
			},
		)

		// Concatenate server certificate and key to PEM file
		f, err = os.OpenFile(fmt.Sprintf("mongodb-server%d.mongodb.com.pem", v), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		crt, err := os.ReadFile(fmt.Sprintf("mongodb-server%d.mongodb.com.crt", v))
		if err != nil {
			log.Fatal(err)
		}
		if _, err = f.Write(crt); err != nil {
			log.Fatal(err)
		}
		key, err := os.ReadFile(fmt.Sprintf("mongodb-server%d.mongodb.com.key", v))
		if err != nil {
			log.Fatal(err)
		}
		if _, err = f.Write(key); err != nil {
			log.Fatal(err)
		}
		if err = f.Close(); err != nil {
			log.Fatal(err)
		}
	}
}

func verify(config VerifyConfig) {
	// Check files exist

	// Verify signatures
}

type CA struct {
	CertificatePEMFile string
}

type VerifyConfig struct {
	CA CA
	Hosts []Host
}

type Host struct {
	Hostname string
	IsMongoDBServer bool
	CertificatePEMFile string
}

func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		fmt.Println()
		fmt.Println("$ mongossl [command]")
		fmt.Println()
		fmt.Println("Commands:")
		fmt.Println()
		fmt.Println("	generate		Generate a set of valid and invalid certificates for testing purposes.")
		fmt.Println("	verify			Verify certificates.")
	} else if args[0] == "generate" {
		fmt.Println("Generate a set of valid and invalid certificates for testing purposes...")
		generate()
	} else if args[0] == "verify" {
		if args[1] == "--help" {
			// Print --help info
			fmt.Println()
			fmt.Println("$ mongossl verify [options]")
			fmt.Println()
			fmt.Println("Options:")
			fmt.Println()
			fmt.Println("	--file		Path to verify configuration file.")
		} else if contains(args, "--file") {
			fmt.Println("Verify certificates")

			// Read and parse config file
			filePath := args[index(args, "--file") + 1]
			data, err := os.ReadFile(filePath)
			if err != nil {
				log.Fatal(err)
			}
			var config VerifyConfig
			err = json.Unmarshal(data, &config)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%+v\n", config)
			
			verify(config)
		}
	}
}
