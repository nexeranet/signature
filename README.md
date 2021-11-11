<pre>
                                          _
 _ __   _____  _____ _ __ __ _ _ __   ___| |_
| '_ \ / _ \ \/ / _ \ '__/ _` | '_ \ / _ \ __|
| | | |  __/>  <  __/ | | (_| | | | |  __/ |_
|_| |_|\___/_/\_\___|_|  \__,_|_| |_|\___|\__|
</pre>
# Signature
## Generate crt and key 
openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout example.com.key -days 730 -out example.com.crt

```go

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

```
