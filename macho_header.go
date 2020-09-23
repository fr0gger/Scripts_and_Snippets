package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
)

// GLOBAL Variable
//var bin = "../../Downloads/macho.a.out"
var magicValue64 = []byte{0xCF, 0xFA, 0xED, 0xFE} // MachO 64
var magicValue32 = []byte{0xCE, 0xFA, 0xED, 0xFE} // MachO 32 FE ED FA CE

/*type mach_header struct {
	uint32_t      magic      // mach magic number
	cpu_type_t    cputype    // cpu specifier
	cpu_subtype_t cpusubtype // cpu subtype specifier
	uint32_t      filetype   // type of mach-o e.g. exec, dylib ...
	uint32_t      ncmds      // number of load commands
	uint32_t      sizeofcmds // size of load command region
	uint32_t      flags      // flags
	uint32_t      reserved   // *64-bit only* reserved
}*/

func main() {
	path := "../../Downloads/macho.a.out"

	file, err := os.Open(path)
	if err != nil {
		log.Fatal("Error while opening file", err)
	}
	defer file.Close()

	fmt.Printf("[+] %s opened\n", path)

	headerfile := readNextBytes(file, 4)
	//fmt.Printf("%s", hex.Dump(headerfile))

	// Check if mach-o
	if bytes.Equal(headerfile, magicValue64) {
		fmt.Printf("[+] Mach-O 64 bit\n")
	} else if bytes.Equal(headerfile, magicValue32) {
		fmt.Printf("[+] Mach-O 32 bit\n")
	} else {
		fmt.Printf("[-] Not Supported format\n")
	}
}

func readNextBytes(file *os.File, number int) []byte {
	bytes := make([]byte, number)

	_, err := file.Read(bytes)
	if err != nil {
		log.Fatal(err)
	}

	return bytes
}
