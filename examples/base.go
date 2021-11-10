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
	pong := signature.GL().Ping()
	fmt.Println("Pong:", pong)

}
