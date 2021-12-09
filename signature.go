package signature

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"sync"
)

type Signature struct {
	sync.RWMutex
	Key     *rsa.PrivateKey
	Cert    *x509.Certificate
	isReady bool
}

var GSignature *Signature = &Signature{}

func GL() *Signature {
	if !GSignature.isReady {
		log.Fatalf("Please setup global signature by using function - SetupGlobalSignature")
	}
	return GSignature
}

func NewSignature(certFilePath, keyFilePath string) (sig *Signature, err error) {
	key, err := readKey(keyFilePath)
	if err != nil {
		return sig, err
	}
	cert, err := readCertificate(certFilePath)
	if err != nil {
		return sig, err
	}
	return &Signature{
		Key:     key,
		Cert:    cert,
		isReady: true,
	}, nil
}

func SetupGlobalSignature(certFilePath, keyFilePath string) error {
	GSignature.Lock()
	defer GSignature.Unlock()
	sig, err := NewSignature(certFilePath, keyFilePath)
	if err != nil {
		return err
	}
	GSignature = sig
	return nil
}

// Read RSA key from file
func readKey(filename string) (*rsa.PrivateKey, error) {

	data, err := ioutil.ReadFile(filename)

	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)

	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("can`t decode rsa file data. %s", filename)
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)

	if err != nil {
		return nil, err
	}

	return key, nil
}

// Read RSA certificate from file
func readCertificate(filename string) (*x509.Certificate, error) {

	data, err := ioutil.ReadFile(filename)

	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)

	if block == nil {
		return nil, fmt.Errorf("can`t decode rsa file data. %s", filename)
	}

	var cert *x509.Certificate

	cert, err = x509.ParseCertificate(block.Bytes)

	if err != nil {
		return nil, err
	}

	return cert, nil
}
