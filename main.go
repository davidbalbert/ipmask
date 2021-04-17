package main

import (
	"errors"
	"fmt"
	"log"
	"math"
	"math/bits"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

var prefixLength = regexp.MustCompile(`/(\d+)`)
var dottedQuad = regexp.MustCompile(`(\d{1,3}).(\d{1,3}).(\d{1,3}).(\d{1,3})`)

func parsePrefixLength(input string) (net.IPMask, error) {
	match := prefixLength.FindStringSubmatch(input)

	if len(match) == 0 {
		return nil, errors.New("invalid prefix length")
	}

	n, err := strconv.Atoi(match[1])

	if err != nil {
		return nil, err
	}

	return net.CIDRMask(n, 32), nil
}

func parseMask(input string) (net.IPMask, error) {
	match := dottedQuad.FindStringSubmatch(input)

	if len(match) == 0 {
		return nil, fmt.Errorf("%s is not a valid netmask or inverse mask", input)
	}

	n1, err := strconv.ParseUint(match[1], 10, 32)
	if err != nil {
		return nil, err
	}

	n2, err := strconv.ParseUint(match[2], 10, 32)
	if err != nil {
		return nil, err
	}

	n3, err := strconv.ParseUint(match[3], 10, 32)
	if err != nil {
		return nil, err
	}

	n4, err := strconv.ParseUint(match[4], 10, 32)
	if err != nil {
		return nil, err
	}

	if n1 > 255 || n2 > 255 || n3 > 255 || n4 > 255 {
		return nil, fmt.Errorf("%s is not a valid netmask or inverse mask", input)
	}

	n := uint32(n1<<24 | n2<<16 | n3<<8 | n4)
	ones := bits.OnesCount32(n)

	if n>>(32-ones) == uint32(math.Pow(2, float64(ones))-1) {
		// netmask
		return net.CIDRMask(ones, 32), nil
	} else if n == uint32(math.Pow(2, float64(ones))-1) {
		// inverse mask
		return net.CIDRMask(32-ones, 32), nil
	} else {
		return nil, fmt.Errorf("%s is not a valid netmask or inverse mask", input)
	}
}

func prefix(mask net.IPMask) string {
	ones, _ := mask.Size()

	return fmt.Sprintf("/%d", ones)
}

func netmask(mask net.IPMask) string {
	ones, _ := mask.Size()

	n := uint32(math.Pow(2, float64(ones))-1) << (32 - ones)

	return fmt.Sprintf("%d.%d.%d.%d", (n>>24)&0xff, (n>>16)&0xff, (n>>8)&0xff, n&0xff)
}

func inverse(mask net.IPMask) string {
	ones, _ := mask.Size()

	n := uint32(math.Pow(2, 32-float64(ones)) - 1)

	return fmt.Sprintf("%d.%d.%d.%d", (n>>24)&0xff, (n>>16)&0xff, (n>>8)&0xff, n&0xff)
}

func usable(mask net.IPMask) uint32 {
	ones, _ := mask.Size()

	return uint32(math.Pow(2, 32-float64(ones)) - 2)
}

func commas(n uint32) string {
	p := message.NewPrinter(language.English)

	return p.Sprintf("%d", n)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s netmask-or-subnet\n", os.Args[0])
		os.Exit(1)
	}

	input := os.Args[1]

	var mask net.IPMask

	if string(input[0]) == "/" {
		var err error
		mask, err = parsePrefixLength(input)

		if err != nil {
			log.Fatal(err)
		}
	} else if strings.Contains(input, "/") {
		_, ipnet, err := net.ParseCIDR(input)

		if err != nil {
			log.Fatal(err)
		}

		mask = ipnet.Mask
	} else {
		var err error
		mask, err = parseMask(input)

		if err != nil {
			log.Fatal(err)
		}
	}

	if mask != nil {
		fmt.Printf("CIDR = .....................: %s\n", prefix(mask))
		fmt.Printf("Netmask = ..................: %s\n", netmask(mask))
		fmt.Printf("Netmask (hex) = ............: 0x%s\n", mask.String())
		fmt.Printf("Wildcard Bits = ............: %s\n", inverse(mask))
		fmt.Printf("Usable IP Addresses = ......: %s\n", commas(usable(mask)))
	}
}
