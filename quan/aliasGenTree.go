package quan

import (
	"IPv6/utils"
	"net"
	"sort"
	"fmt"
)

func dis(alias1, alias2 string) []int {
	difPos := make([]int, 0)

	// find /
	slashPos1 := len(alias1) - 1
	slashPos2 := len(alias2) - 1
	for {
		if alias1[slashPos1] == '/' {
			break
		}
		slashPos1 --
	}
	for {
		if alias2[slashPos2] == '/' {
			break
		}
		slashPos2 --
	}
	len1 := alias1[slashPos1 + 1:]
	len2 := alias2[slashPos2 + 1:]
	if len1 != len2 {
		return difPos
	}
	for i := 0; i < len(alias1); i ++ {
		if alias1[i] != alias2[i] {
			difPos = append(difPos, i)
		}
	}
	return difPos
}

func expandPattern(patternStr string, patternNybble []bool) []string {
	pfxArray := make([]string, 0)
	wildArray := make([]int, 0)
	for i, nybble := range patternNybble {
		if nybble {
			wildArray = append(wildArray, i)
		}
	}
	if len(wildArray) == 0 {
		return pfxArray
	}
	for i := 0; i < (16 << len(wildArray)); i ++ {
		tmp := i
		nowStr := ""
		lastPos := -1
		for _, wildPos := range wildArray {
			nowChar := utils.ToHex(uint8(tmp % 16))
			tmp /= 16
			nowStr += patternStr[lastPos + 1 : wildPos] + nowChar
			lastPos = wildPos
		}
		nowStr += patternStr[lastPos + 1:]
		pfxArray = append(pfxArray, nowStr)
	}
	return pfxArray
}

type AliasGenerator struct{
	aliasStrArray []string
	maxDis        int
}

func NewAliasGenerator(aliasStrArray []string, maxDis int) *AliasGenerator {
	fmt.Print()
	newArray := make([]string, len(aliasStrArray))
	for i, aliasStr := range aliasStrArray {
		_, pfx, _ := net.ParseCIDR(aliasStr)
		pfxBits := utils.Pfx2Bits(pfx)[0]
		newArray[i] = pfxBits.ToPrefix6()
	}
	return &AliasGenerator{
		aliasStrArray: newArray,
		maxDis: maxDis,
	}
}

func (ag *AliasGenerator) Gen() []string {
	sort.Strings(ag.aliasStrArray)
	genPfxes := make(map[string]bool)
	lastAliasStr := ag.aliasStrArray[0]
	patternNybble := make([]bool, len(lastAliasStr))
	aliasSet := make(map[string]bool)
	aliasSet[lastAliasStr] = true
	for i := 1; i < len(ag.aliasStrArray); i ++ {
		fmt.Printf("\r%d/%d %d new prefixes have generated...", i + 1, len(ag.aliasStrArray), len(genPfxes))
		nowAliasStr := ag.aliasStrArray[i]
		difPos := dis(lastAliasStr, nowAliasStr)
		if len(difPos) == 0 || len(difPos) > ag.maxDis {
			// finish the old cluster
			pfxStrArray := expandPattern(lastAliasStr, patternNybble)
			for _, pfxStr := range pfxStrArray {
				if _, ok := aliasSet[pfxStr]; !ok {
					genPfxes[pfxStr] = true
				}
			}
			// start a new cluster
			lastAliasStr = nowAliasStr
			aliasSet = make(map[string]bool)
			aliasSet[lastAliasStr] = true
			patternNybble = make([]bool, len(lastAliasStr))
		} else {  // expand now pattern
			aliasSet[nowAliasStr] = true
			for _, pos := range difPos {
				patternNybble[pos] = true
			}
			lastAliasStr = nowAliasStr
		}
	}
	genPfxArray := make([]string, 0)
	for pfx := range genPfxes {
		genPfxArray = append(genPfxArray, pfx)
	}
	return genPfxArray
}