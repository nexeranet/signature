<pre>
                                          _
 _ __   _____  _____ _ __ __ _ _ __   ___| |_
| '_ \ / _ \ \/ / _ \ '__/ _` | '_ \ / _ \ __|
| | | |  __/>  <  __/ | | (_| | | | |  __/ |_
|_| |_|\___/_/\_\___|_|  \__,_|_| |_|\___|\__|
</pre>
# Signature

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
	pong := signature.GL().Ping()
	fmt.Println("Pong:", pong)

}

```
