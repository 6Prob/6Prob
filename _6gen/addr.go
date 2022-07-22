package _6gen

import (
	"IPv6/utils"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

const (
	AddrBitsLen         = 128
	AddrBytesLen        = 16
	AddrWordsLen        = 8
	UInt16Max    uint16 = 0xffff
	uInt64Max    uint64 = 0xffffffffffffffff
)

type Uint128 struct {
	Hi, Lo uint64
}

type Uint128Set map[Uint128]bool

type Wildcard struct {
	val uint16
}

func (w *Wildcard) IsRange() bool {
	// Tell whether this wildcard is a range.
	hasValue := false
	isRange := false
	for i := 0; i < 16; i++ {
		flag := uint16(1) << i
		if w.val&flag != 0 {
			if hasValue {
				isRange = true
				break
			} else {
				hasValue = true
			}
		}
	}
	return isRange
}

func (w *Wildcard) GetVal() []uint8 {
	// Get all possible values of the wildcard.
	var valList []uint8
	var i uint8 = 0
	for tempVal := w.val; tempVal != 0; tempVal >>= 1 {
		if tempVal&1 != 0 {
			valList = append(valList, i)
		}
		i++
	}
	return valList
}

func (w *Wildcard) AddVal(trueVal uint8) {
	w.val = w.val | (1 << trueVal)
}

func (w *Wildcard) SetVal(trueVal uint8) {
	w.val = 1 << trueVal
}

func (w *Wildcard) SetAll(gran int) {
	w.val = UInt16Max >> (16 - (1 << gran))
}

func WildOR(w1, w2 Wildcard) Wildcard {
	var w Wildcard
	w.val = w1.val | w2.val
	return w
}

func WildAND(w1, w2 Wildcard) Wildcard {
	// w2 minus the intersection with w1
	var w Wildcard
	w.val = w1.val & w2.val
	return w
}

func GetWildDistance(w1, w2 Wildcard) int {
	// If w1 covers w2 or w2 covers w1, return 1;
	// Otherwise, return 0.
	and := WildAND(w1, w2)
	if and.val == w1.val || and.val == w2.val {
		return 0
	} else {
		return 1
	}
}

func (w *Wildcard) GetNVal() int {
	return len(w.GetVal())
}

type Addr6 struct {
	IP      []Wildcard
	Gran    int // can only be 1,2,4
	Integer Uint128
}

func NewAddr6(gran int, prefixLen int) *Addr6 {
	ipLen := prefixLen / gran
	if prefixLen % gran > 0 {
		ipLen ++
	}
	addr := &Addr6{
		IP:   make([]Wildcard, ipLen),
		Gran: gran,
	}
	return addr
}

func NewAddr6FromString(ipStr string, gran int) *Addr6 {
	addr := NewAddr6(gran, AddrBitsLen)

	ipFullSeg := utils.SplitIPStr(ipStr)
	ipByteSeg, err := hex.DecodeString(strings.Join(ipFullSeg, ""))
	if err != nil {
		fmt.Println(err)
		return nil
	}
	var flag byte = 0xff >> (8 - addr.Gran)
	for i := 0; i < 16; i++ {
		for j := 0; j < 8/addr.Gran; j++ {
			nShift := 8 - (j+1)*addr.Gran
			addr.IP[i*8/addr.Gran+j].SetVal(uint8((ipByteSeg[i] >> nShift) & flag))
		}
	}
	addr.Integer = addr.ToInt128()
	return addr
}

func NewPrefix6FromString(prefixStr string, gran int) *Addr6 {
	prefixSeg := strings.Split(prefixStr, "/")
	ipStr := utils.GetFullIP(prefixSeg[0])
	prefixLen, err := strconv.Atoi(prefixSeg[1])
	if err != nil {
		panic("Prefix conversion error.")
	}

	addr := NewAddr6FromString(ipStr, gran)
	mod := prefixLen % gran
	pos := prefixLen / gran
	if mod > 0 {
		val := addr.IP[pos].GetVal()[0]
		for i := uint8(1); i < (1 << (gran - mod)); i ++ {
			addr.IP[pos].AddVal(val + i)
		}
		pos ++
	}
	for i := pos; i < len(addr.IP); i ++ {
		addr.IP[i].SetAll(gran)
	}
	return addr
}

func NewAddr6FromInt(addrInt Uint128, gran int) *Addr6 {
	addr := NewAddr6(gran, AddrBitsLen)
	addr.Integer = addrInt
	hiLen := AddrBitsLen / gran / 2
	mask := uInt64Max >> (64 - gran)
	for i := 0; i < hiLen; i++ {
		addr.IP[i].SetVal(uint8((addrInt.Hi >> (64 - gran*(i+1))) & mask))
	}
	for i := hiLen; i < len(addr.IP); i++ {
		addr.IP[i].SetVal(uint8((addrInt.Lo >> (64 - gran*(i-hiLen+1))) & mask))
	}
	return addr
}

func (addr *Addr6) Copy() *Addr6 {
	newIP := make([]Wildcard, len(addr.IP))
	copy(newIP, addr.IP)
	return &Addr6{
		IP:      newIP,
		Gran:    addr.Gran,
		Integer: addr.Integer,
	}
}

func (addr *Addr6) IsRange() bool {
	for i := len(addr.IP) - 1; i > -1; i-- {
		if addr.IP[i].IsRange() {
			return true
		}
	}
	return false
}

func (addr *Addr6) GetIntRange() uint64 {
	var _range uint64 = 1
	for i := 0; i < len(addr.IP); i++ {
		_range *= uint64(addr.IP[i].GetNVal())
	}
	return _range
}

func (addr *Addr6) GetFloatRange() float64 {
	var _range float64 = 1
	for i := 0; i < len(addr.IP); i++ {
		_range *= float64(addr.IP[i].GetNVal())
	}
	return _range
}

func (addr *Addr6) ToString() string {
	// If it is an address, print its hex form.
	// If it is a range, print its start and end address.
	startStr, endStr := addr.ToStrings()
	if endStr == "" {
		return startStr
	} else {
		return startStr + " - " + endStr
	}
}

func (addr *Addr6) ToStrings() (string, string) {
	var startStr, endStr string
	isRange := addr.IsRange()
	// word -> 0-f -> gran
	for i := 0; i < 8; i++ {
		for j := 0; j < 4; j++ {
			startHex := uint8(0)
			endHex := uint8(0)
			for k := 0; k < 4/addr.Gran; k++ {
				granPos := (i*16+j*4)/addr.Gran + k
				if granPos >= len(addr.IP) {
					return startStr, endStr
				}
				nShift := 4 - (k+1)*addr.Gran
				hexRange := addr.IP[granPos].GetVal()
				startHex += hexRange[0] << nShift
				if isRange {
					endHex += hexRange[len(hexRange)-1] << nShift
				}
			}
			startStr += utils.ToHex(startHex)
			if isRange {
				endStr += utils.ToHex(endHex)
			}
		}
		if i != 7 {
			startStr += ":"
			if isRange {
				endStr += ":"
			}
		}
	}
	return startStr, endStr
}

func (addr *Addr6) ToInt128() Uint128 {
	// only address (not range) can be transformed to int128
	hiLen := AddrBitsLen / addr.Gran / 2
	hiEnd := hiLen
	if hiEnd > len(addr.IP) {
		hiEnd = len(addr.IP)
	}
	addrInt := Uint128{}
	for i := 0; i < hiEnd; i++ {
		addrInt.Hi += uint64(addr.IP[i].GetVal()[0]) * uint64(1<<(64-addr.Gran*(i+1)))
	}
	for i := hiLen; i < len(addr.IP); i++ {
		addrInt.Lo += uint64(addr.IP[i].GetVal()[0]) * uint64(1<<(64-addr.Gran*(i-hiLen+1)))
	}
	return addrInt
}

func CombineAddr(addr1, addr2 *Addr6, tight bool) *Addr6 {
	// Combine two give addresses to a larger address space
	// tight means whether other values on positions with different values can be attained
	if addr1.Gran != addr2.Gran {
		panic("Granularity does not match")
	}
	combinedAddr := NewAddr6(addr1.Gran, addr1.Gran * len(addr1.IP))
	for i := 0; i < len(combinedAddr.IP); i++ {
		if tight {
			combinedAddr.IP[i] = WildOR(addr1.IP[i], addr2.IP[i])
		} else {
			if addr1.IP[i].val != addr2.IP[i].val {
				combinedAddr.IP[i].SetAll(combinedAddr.Gran)
			} else {
				combinedAddr.IP[i] = addr1.IP[i]
			}
		}
	}
	return combinedAddr
}

func (addrRange *Addr6) expandRangeAt(pos int) []*Addr6 {
	gran := addrRange.Gran
	valArray := addrRange.IP[pos].GetVal()
	expandedArray := make([]*Addr6, len(valArray))
	if len(valArray) < 2 {
		return []*Addr6{addrRange}
	}
	for i, val := range valArray {
		newAddr := NewAddr6(gran, len(addrRange.IP)*gran)
		for j := 0; j < len(addrRange.IP); j++ {
			newAddr.IP[j] = addrRange.IP[j]
		}
		newAddr.IP[pos].SetVal(val)
		expandedArray[i] = newAddr
	}
	return expandedArray
}

func (addrRange *Addr6) ExpandRange() []*Addr6 {
	// Expand the range to an array of addresses
	var lastPosArray []*Addr6
	var nowPosArray []*Addr6
	lastPosArray = append(lastPosArray, addrRange)
	for i := 0; i < len(addrRange.IP); i ++ {
		for _, lastPosRange := range lastPosArray {
			expandedRange := lastPosRange.expandRangeAt(i)
			nowPosArray = append(nowPosArray, expandedRange...)
		}
		lastPosArray = nowPosArray
		nowPosArray = nil
	}
	for _, addr := range lastPosArray {
		addr.Integer = addr.ToInt128()
	}
	return lastPosArray
}

func GetIntersection(addr1, addr2 *Addr6) []*Addr6 {
	interAddr := NewAddr6(addr1.Gran, AddrBitsLen)
	for i := 0; i < len(addr1.IP); i++ {
		interAddr.IP[i] = WildAND(addr1.IP[i], addr2.IP[i])
	}
	return interAddr.ExpandRange()
}

func GetHammingDistance(addr1, addr2 *Addr6) int {
	dis := 0
	for i := 0; i < len(addr1.IP); i++ {
		dis += GetWildDistance(addr1.IP[i], addr2.IP[i])
	}
	return dis
}

func (addr *Addr6) SearchInFile(filename string) []string {
	startIP, endIP := addr.ToStrings()
	if endIP == "" {
		endIP = startIP
	}
	return utils.SearchPrefix6FromFS(filename, startIP, endIP)
}

func (addr1 *Addr6) Equal(addr2 *Addr6) bool {
	for i := 0; i < len(addr1.IP); i ++ {
		if addr1.IP[i] != addr2.IP[i] {
			return false
		}
	}
	return true
}
