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

var (
	prefixLength = regexp.MustCompile(`/(\d+)`)
	dottedQuad   = regexp.MustCompile(`(\d{1,3}).(\d{1,3}).(\d{1,3}).(\d{1,3})`)
	hex          = regexp.MustCompile(`0x([a-fA-F0-9]{8})`)
)

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

func interpretMask(n uint32) (net.IPMask, error) {
	ones := bits.OnesCount32(n)

	if n>>(32-ones) == uint32(math.Pow(2, float64(ones))-1) {
		// netmask
		return net.CIDRMask(ones, 32), nil
	} else if n == uint32(math.Pow(2, float64(ones))-1) {
		// inverse mask
		return net.CIDRMask(32-ones, 32), nil
	} else {
		return nil, fmt.Errorf("invalid netmask or inverse mask")
	}
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

	mask, err := interpretMask(n)
	if err != nil {
		return nil, fmt.Errorf("%s is not a valid netmask or inverse mask", input)
	}

	return mask, nil
}

func parseHex(input string) (net.IPMask, error) {
	match := hex.FindStringSubmatch(input)

	if len(match) == 0 {
		return nil, fmt.Errorf("%s is not a valid netmask or inverse mask (hex values need 8 chars)", input)
	}

	n, err := strconv.ParseUint(match[1], 16, 32)
	if err != nil {
		return nil, err
	}

	mask, err := interpretMask(uint32(n))
	if err != nil {
		return nil, fmt.Errorf("%s is not a valid netmask or inverse mask", input)
	}

	return mask, nil
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

func total(mask net.IPMask) uint32 {
	ones, _ := mask.Size()

	return uint32(math.Pow(2, 32-float64(ones)))
}

func usable(mask net.IPMask) uint32 {
	ones, _ := mask.Size()

	return uint32(math.Max(math.Pow(2, 32-float64(ones))-2, 0))
}

func commas(n uint32) string {
	p := message.NewPrinter(language.English)

	return p.Sprintf("%d", n)
}

func ipToUint(ip net.IP) uint32 {
	bytes := []byte(ip.To4())

	if bytes == nil {
		return 0
	}

	return uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
}

func uintToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s netmask-or-subnet\n", os.Args[0])
		os.Exit(1)
	}

	input := os.Args[1]

	var mask net.IPMask
	var ip net.IP
	var ipnet *net.IPNet

	switch {
	case string(input[0]) == "/":
		var err error
		mask, err = parsePrefixLength(input)

		if err != nil {
			log.Fatal(err)
		}
	case strings.Contains(input, "/"):
		var err error
		ip, ipnet, err = net.ParseCIDR(input)

		if err != nil {
			log.Fatal(err)
		}

		mask = ipnet.Mask
	case strings.Contains(input, "."):
		var err error
		mask, err = parseMask(input)

		if err != nil {
			log.Fatal(err)
		}
	case strings.HasPrefix(input, "0x"):
		var err error
		mask, err = parseHex(input)

		if err != nil {
			log.Fatal(err)
		}
	default:
		var err error
		mask, err = parsePrefixLength(fmt.Sprintf("/%s", input))

		if err != nil {
			log.Fatal(err)
		}
	}

	fmt.Println()
	fmt.Println("------------------------------------------------")
	fmt.Println("           TCP/IP NETWORK INFORMATION           ")
	fmt.Println("------------------------------------------------")

	if ip != nil {
		fmt.Printf("IP Entered = ..................: %s\n", ip.String())
	}
	fmt.Printf("CIDR = ........................: %s\n", prefix(mask))
	fmt.Printf("Netmask = .....................: %s\n", netmask(mask))
	fmt.Printf("Netmask (hex) = ...............: 0x%s\n", mask.String())
	fmt.Printf("Wildcard Bits = ...............: %s\n", inverse(mask))
	if ip == nil {
		fmt.Printf("Usable IP Addresses = .........: %s\n", commas(usable(mask)))
	}

	if ipnet != nil {
		n := ipToUint(ipnet.IP)
		broadcast := n + total(ipnet.Mask) - 1
		first := n + 1
		last := broadcast - 1

		var firstAddr, lastAddr string
		if broadcast-n > 1 {
			firstAddr = uintToIP(first).String()
			lastAddr = uintToIP(last).String()
		} else {
			firstAddr = "<none>"
			lastAddr = "<none>"
		}

		fmt.Println("------------------------------------------------")
		fmt.Printf("Network Address = .............: %s\n", ipnet.IP.String())
		fmt.Printf("Broadcast Address = ...........: %s\n", uintToIP(broadcast))
		fmt.Printf("Usable IP Addresses = .........: %s\n", commas(usable(mask)))
		fmt.Printf("First Usable IP Address = .....: %s\n", firstAddr)
		fmt.Printf("Last Usable IP Address = ......: %s\n", lastAddr)
	}

	fmt.Println()
}
