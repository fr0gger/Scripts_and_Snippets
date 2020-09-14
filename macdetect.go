package main

import (
    "fmt"
    "log"
    "net"
    "strings"
)

func getMacAddr() ([]string, error) {
    ifas, err := net.Interfaces()
    if err != nil {
        return nil, err
    }
    var as []string
    for _, ifa := range ifas {
        a := ifa.HardwareAddr.String()
        if a != "" {
            as = append(as, a)
        }
    }
    return as, nil
}

func main() {
    // Blacklist VM mac address
    var macvm = []string{"08:00:27", "00:0C:29", "00:1C:14", "00:50:56", "00:05:69"}

    as, err := getMacAddr()
    if err != nil {
        log.Fatal(err)
    }

    for i, s:= range macvm {
        for _, a := range as {
            str := strings.ToUpper(a)
            if str[0:8] == s[0:8] {
                fmt.Println("VM detected!")
		fmt.Println(i, s)
            } 
         }
    }
}
