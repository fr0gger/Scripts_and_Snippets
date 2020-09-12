package main

import (
    "encoding/base64"
    "fmt"
    "os"
)

func main() {

    arg1 := os.Args[1]

    encoded := base64.StdEncoding.EncodeToString([]byte(arg1))
    fmt.Println(encoded)

    decoded, err := base64.StdEncoding.DecodeString(encoded)
    if err != nil {
        panic("error")
    }
    fmt.Println(string(decoded))
}
