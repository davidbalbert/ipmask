package main

import (
	"flag"
	"fmt"
	"log"
	"math/big"
	"math/bits"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var ipv6 = false

var dottedQuad = regexp.MustCompile(`(\d{1,3}).(\d{1,3}).(\d{1,3}).(\d{1,3})`)

func parsePrefixLength(input string) (net.IPMask, error) {
	if len(input) < 1 {
		return nil, fmt.Errorf("invalid prefix length")
	}

	n, err := strconv.Atoi(input[1:])
	if err != nil {
		return nil, fmt.Errorf("invalid prefix length")
	}

	if n < 0 || n > 128 {
		return nil, fmt.Errorf("invalid prefix length (must be between 0 and 128)")
	}

	if n > 32 {
		ipv6 = true
	}

	if ipv6 {
		return net.CIDRMask(n, 128), nil
	} else {
		return net.CIDRMask(n, 32), nil
	}
}

func interpretMask(n uint32) (net.IPMask, error) {
	ones := bits.OnesCount32(n)

	if n>>(32-ones) == (1<<ones)-1 {
		// netmask
		return net.CIDRMask(ones, 32), nil
	} else if n == (1<<ones)-1 {
		// inverse mask
		return net.CIDRMask(32-ones, 32), nil
	} else {
		return nil, fmt.Errorf("invalid netmask or inverse mask")
	}
}

func getNum(s string) uint64 {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		panic(err)
	}

	return n
}

func parseMask(input string) (net.IPMask, error) {
	match := dottedQuad.FindStringSubmatch(input)

	if len(match) == 0 {
		return nil, fmt.Errorf("%s is not a valid netmask or inverse mask", input)
	}

	n1 := getNum(match[1])
	n2 := getNum(match[2])
	n3 := getNum(match[3])
	n4 := getNum(match[4])

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
	if len(input) != 10 {
		return nil, fmt.Errorf("%s is not a valid netmask or inverse mask (hex values need 8 chars)", input)
	}

	n, err := strconv.ParseUint(input[2:], 16, 32)
	if err != nil {
		return nil, fmt.Errorf("%s is not a valid netmask or inverse mask: %w", input, err)
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

	n := ((1 << ones) - 1) << (32 - ones)

	return fmt.Sprintf("%d.%d.%d.%d", (n>>24)&0xff, (n>>16)&0xff, (n>>8)&0xff, n&0xff)
}

func inverse(mask net.IPMask) string {
	ones, _ := mask.Size()

	n := (1 << (32 - ones)) - 1

	return fmt.Sprintf("%d.%d.%d.%d", (n>>24)&0xff, (n>>16)&0xff, (n>>8)&0xff, n&0xff)
}

func b(n int64) *big.Int {
	return big.NewInt(n)
}

func max(x, y *big.Int) *big.Int {
	if x.Cmp(y) == -1 {
		return y
	} else {
		return x
	}
}

func total(mask net.IPMask) *big.Int {
	ones, bits := mask.Size()

	return new(big.Int).Exp(b(2), b(int64(bits-ones)), nil)
}

func usable(mask net.IPMask) *big.Int {
	n := total(mask)

	if ipv6 {
		return n
	}

	n.Sub(n, b(2))
	return max(n, b(0))
}

func reverse(s string) string {
	runes := []rune(s)

	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}

	return string(runes)
}

func chunk(s string, n int) []string {
	var res []string

	for i := 0; i < len(s); i = i + n {
		var end int
		if i+n > len(s) {
			end = len(s)
		} else {
			end = i + n
		}

		res = append(res, s[i:end])
	}

	return res
}

func commas(n *big.Int) string {
	s := n.String()

	chunked := chunk(reverse(s), 3)

	return reverse(strings.Join(chunked, ","))
}

func ipToUint(ip net.IP) *big.Int {
	var bytes []byte

	ip4 := ip.To4()

	if ip4 != nil {
		bytes = []byte(ip4)
	} else {
		bytes = []byte(ip)
	}

	return new(big.Int).SetBytes(bytes)
}

func uintToIP(n *big.Int) net.IP {
	var bytes []byte

	// TODO: this is asymetric from ipToUint. Here, we check whether we're
	// in IPv6 mode. There we check if the address is a v4 addres. Is this a
	// problem?
	//
	// We could do something like assume ipv4 in the case where n is between
	// 1.0.0.0 and 254.255.255.255 (0.0.0.0/8 and 255.0.0.0/8 are invalid v6
	// addresses and 0.0.0.1 overlaps with ::1). I'm not sure if this is a
	// good idea.
	if ipv6 {
		bytes = make([]byte, 16)
	} else {
		bytes = make([]byte, 4)
	}

	return net.IP(n.FillBytes(bytes))
}

func main() {
	log.SetFlags(0)

	flag.BoolVar(&ipv6, "6", false, "Force IPv6")
	flag.Parse()

	if flag.NArg() != 1 {
		log.Fatalf("usage: %s [-6] netmask-or-subnet\n", os.Args[0])
	}

	input := flag.Arg(0)

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

		if ip.To4() == nil {
			ipv6 = true
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
	if ipnet != nil {
		fmt.Println("           TCP/IP NETWORK INFORMATION           ")
	} else {
		fmt.Println("         TCP/IP SUBNET MASK EQUIVALENTS         ")

	}
	fmt.Println("------------------------------------------------")

	if ip != nil {
		fmt.Printf("IP Entered = ..................: %s\n", ip.String())
	}

	if ipv6 {
		fmt.Printf("Prefix = ......................: %s\n", prefix(mask))
	} else {
		fmt.Printf("CIDR = ........................: %s\n", prefix(mask))
		fmt.Printf("Netmask = .....................: %s\n", netmask(mask))
		fmt.Printf("Netmask (hex) = ...............: 0x%s\n", mask.String())
		fmt.Printf("Wildcard Bits = ...............: %s\n", inverse(mask))
	}

	if ip == nil {
		fmt.Printf("Usable IP Addresses = .........: %s\n", commas(usable(mask)))
	}

	if ipnet != nil {
		n := ipToUint(ipnet.IP)
		broadcast := new(big.Int).Add(n, total(ipnet.Mask))
		broadcast.Sub(broadcast, b(1))

		first := new(big.Int).Add(n, b(1))
		last := new(big.Int).Sub(broadcast, b(1))

		size := new(big.Int).Sub(broadcast, n)
		var firstAddr, lastAddr string
		if size.Sign() == 1 {
			firstAddr = uintToIP(first).String()
			lastAddr = uintToIP(last).String()
		} else {
			firstAddr = "<none>"
			lastAddr = "<none>"
		}

		fmt.Println("------------------------------------------------")

		if !ipv6 {
			fmt.Printf("Network Address = .............: %s\n", ipnet.IP.String())
			fmt.Printf("Broadcast Address = ...........: %s\n", uintToIP(broadcast))
		}

		fmt.Printf("Usable IP Addresses = .........: %s\n", commas(usable(mask)))
		fmt.Printf("First Usable IP Address = .....: %s\n", firstAddr)
		fmt.Printf("Last Usable IP Address = ......: %s\n", lastAddr)
	}

	fmt.Println()
}
