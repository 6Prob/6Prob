package utils

import (
	"fmt"
	"math/rand"
	"strings"
	"net"
)

// Bits array is an array of 1, 2, 4 bits element
type BitsArray struct {
	bytes []byte
	granLen uint8
}

func NewBitsArray(granLen uint8, bytes []byte) BitsArray {
	bitsLen := granLen * 4
	byteLen := bitsLen / 8
	if bitsLen % 8 != 0 {
		byteLen ++
	}
	var newBytes []byte
	if bytes == nil {
		newBytes = make([]byte, byteLen)
	} else {
		newBytes = bytes
	}
	return BitsArray{
		bytes: newBytes,
		granLen: granLen,
	}
}

func NilSlice() BitsArray {
	return BitsArray{nil, 0}
}

func (ba *BitsArray) Copy() BitsArray {
	bytes := make([]byte, len(ba.bytes))
	copy(bytes, ba.bytes)
	return NewBitsArray(ba.granLen, bytes)
}

func (ba *BitsArray) IndexAt(i uint8) byte {
	// return bits[i]
	if i % 2 == 0 {
		return ba.bytes[i / 2] >> 4
	} else {
		return ba.bytes[i / 2] & 0xf
	}
}

func (ba *BitsArray) Set(i, val byte) {
	// set bits[i] to val
	shift := 8 - (i + 1) * 4 % 8
	if shift == 8 {
		shift = 0
	}
	index := i / 2
	mask := ^(byte(0xf) << shift)
	// clear
	ba.bytes[index] &= mask
	// set
	ba.bytes[index] |= val << shift
}

func (ba *BitsArray) Append(val byte) {
	// append val to the tail of bits
	if ba.granLen * 4 == uint8(len(ba.bytes)) * 8 {
		newBytes := make([]byte, ba.granLen / 2 + 1)
		copy(newBytes, ba.bytes)
		ba.bytes = newBytes
		ba.Set(ba.granLen, val)
		ba.granLen ++
	} else {
		ba.Set(ba.granLen, val)
		ba.granLen ++
	}
}

func (ba *BitsArray) Print() {
	for i := uint8(0); i < ba.granLen; i ++ {
		fmt.Printf("%x", ba.IndexAt(i))
	}
	fmt.Println()
}

func (ba *BitsArray) Len() uint8 {
	return ba.granLen
}

func (ba *BitsArray) Slice(pos ...uint8) BitsArray {
	var beg, end uint8
	beg = pos[0]
	if len(pos) == 1 {
		end = ba.granLen
	} else {
		end = pos[1]
	}
	// get bits[beg:end)
	slice := NewBitsArray(end - beg, nil)
	for i := beg; i < end; i ++ {
		slice.Set(i - beg, ba.IndexAt(i))
	}
	return slice
}

func (ba *BitsArray) Empty() bool {
	return ba.granLen == 0
}

func (ba *BitsArray) Back() byte {
	return ba.IndexAt(ba.granLen - 1)
}

func (ba *BitsArray) RandFill() BitsArray {
	for ba.granLen < 32 {
		ba.Append(byte(rand.Intn(16)))
	}
	return *ba
}

func RandBits(granLen uint8) BitsArray {
	newBits := NewBitsArray(granLen, make([]byte, granLen))
	for i := uint8(0); i < granLen; i ++ {
		newBits.Set(i, byte(rand.Intn(16)))
	}
	return newBits
}

func (ba *BitsArray) ToIPv6() string {
	ipArray := make([]string, 8)
	for i := uint8(0); i < 8; i ++ {
		ipSegArray := make([]string, 4)
		for j := uint8(0); j < 4; j ++ {
			ipSegArray[j] = ToHex(ba.IndexAt(i * 4 + j))
		}
		ipArray[i] = strings.Join(ipSegArray, "")
	}
	return strings.Join(ipArray, ":")
}

func (ba *BitsArray) ToIPv6Wild(wild Indices32) string {
	ipArray := make([]string, 8)
	for i := uint8(0); i < 8; i ++ {
		ipSegArray := make([]string, 4)
		for j := uint8(0); j < 4; j ++ {
			if wild.Has(i * 4 + j) {
				ipSegArray[j] = "*"
			} else {
				ipSegArray[j] = ToHex(ba.IndexAt(i * 4 + j))
			}
		}
		ipArray[i] = strings.Join(ipSegArray, "")
	}
	return strings.Join(ipArray, ":")
}

func (ba *BitsArray) fillZero() BitsArray {
	newBytes := make([]byte, 16)
	for i := 0; i < len(ba.bytes); i ++ {
		newBytes[i] = ba.bytes[i]
	}
	return NewBitsArray(32, newBytes)
}

func (ba *BitsArray) ToPrefix6() string {
	fullBits := ba.fillZero()
	ipStr := fullBits.ToIPv6()
	return fmt.Sprintf("%s/%d", ipStr, ba.granLen * 4)
}

func Pfx2Bits(pfx *net.IPNet) []BitsArray {
	var subPfxBits []BitsArray
	pfxLen, _ := pfx.Mask.Size()
	pfxByteLen := uint8(pfxLen) / 8
	mod8 := pfxLen % 8
	if mod8 != 0 {
		pfxByteLen ++
	}
	pfxGranLen := uint8(pfxLen) / 4
	modGran := uint8(pfxLen) % 4
	if modGran != 0 {
		pfxGranLen ++
	}
	if modGran == 0 {
		newBytes  := []byte(pfx.IP[:pfxByteLen])
		newBits   := NewBitsArray(uint8(pfxGranLen), newBytes)
		subPfxBits = append(subPfxBits, newBits)
	} else {
		nSubPfx := 1 << (4 - pfxLen % 4)
		for i := uint8(0); i < uint8(nSubPfx); i ++ {
			newBytes := make([]byte, pfxByteLen)
			copy(newBytes, []byte(pfx.IP))
			newBytes[pfxByteLen - 1] |= i << (pfxByteLen * 8 - pfxGranLen * 4)
			newBits := NewBitsArray(uint8(pfxGranLen), newBytes)
			subPfxBits = append(subPfxBits, newBits)
		}
	}
	return subPfxBits
}

func (ba *BitsArray) Range() []byte {
	bytes := make([]byte, ba.granLen)
	for i := uint8(0); i < ba.granLen; i ++ {
		bytes[i] = ba.IndexAt(i)
	}
	return bytes
}

func (ba *BitsArray) ByteLen() uint8 {
	return uint8(len(ba.bytes))
}