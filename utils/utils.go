package utils

import (
	"net"
	"strings"
)

const (
	Addr6StrLen = 39
)

func ToHex(x uint8) string {
	if x > 15 {
		panic("Hex can only be between 0-15.")
	}
	switch x {
	case 0:
		return "0"
	case 1:
		return "1"
	case 2:
		return "2"
	case 3:
		return "3"
	case 4:
		return "4"
	case 5:
		return "5"
	case 6:
		return "6"
	case 7:
		return "7"
	case 8:
		return "8"
	case 9:
		return "9"
	case 10:
		return "a"
	case 11:
		return "b"
	case 12:
		return "c"
	case 13:
		return "d"
	case 14:
		return "e"
	case 15:
		return "f"
	}
	return ""
}

func SplitIPStr(ipStr string) []string{
	if ipStr[len(ipStr) - 1] == ':' {
		ipStr = ipStr[:len(ipStr) - 1]
	}
	ipSeg := strings.Split(ipStr, ":")
	var ipFullSeg []string
	for i := 0; i < len(ipSeg); i++ {
		seg := ipSeg[i]
		if seg == "" {
			nIgnore := 9 - len(ipSeg)
			for j := 0; j < nIgnore; j++ {
				ipFullSeg = append(ipFullSeg, "0000")
			}
			continue
		}
		nZero := 4 - len(seg)
		for i := 0; i < nZero; i++ {
			seg = "0" + seg
		}
		ipFullSeg = append(ipFullSeg, seg)
	}
	return ipFullSeg
}

func GetFullIP(ipStr string) string {
	ipFullSeg := SplitIPStr(ipStr)
	return strings.Join(ipFullSeg, ":")
}

func Pfx2Range(pfxStr string) (string, string) {
	_, pfx, _ := net.ParseCIDR(pfxStr)
	startIP := make([]byte, 16)
	endIP := make([]byte, 16)
	for i := range pfx.IP {
		startIP[i] = pfx.IP[i] & pfx.Mask[i]
		endIP[i]   = pfx.IP[i] | (^pfx.Mask[i])
	}
	startBits := NewBitsArray(32, startIP)
	endBits := NewBitsArray(32, endIP)
	return startBits.ToIPv6(), endBits.ToIPv6()
}
