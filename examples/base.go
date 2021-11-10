package main

import (
	"fmt"
	"log"
	"path/filepath"

	"github.com/nexeranet/signature"
)

func main() {
	cert, _ := filepath.Abs("./examples/example.crt")
	key, _ := filepath.Abs("./examples/example.key")

	fmt.Println(cert, key)
	err := signature.SetupGlobalSignature(cert, key)
	if err != nil {
		log.Fatalln(err)
	}
	sign, err := signature.GL().GenerateSign("test")
	if err != nil {
		log.Fatalln(err)
	}
	adm := signature.GL().GetAdminKey()
	fmt.Println("new signature", string(sign))
	fmt.Println("adming signature", string(adm))
	isValid, err := signature.GL().VerifyHash("test", sign)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println("is valid : ", isValid)
}
