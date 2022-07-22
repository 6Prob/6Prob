package main

import (
	"IPv6/quan"
	"IPv6/scanner"
	"IPv6/utils"
	"IPv6/_6gen"
	"fmt"
	"os"
	"testing"
	"time"
	"net"
	"math/rand"
	"math"
)

func TestAliasWithoutBlock(t *testing.T) {
	rand.Seed(0)
	aliasPath := "data/2022-04-22-pfx10-filtered.txt"
	pfxStrArray := utils.ReadAliasFromFS(aliasPath)
	nSlice := 20
	interval := len(pfxStrArray) / nSlice + 1
	for l := 2; l < 3; l ++ {
		outPath := fmt.Sprintf("alias/2022-04-22-pfx10-aliased-org%d.txt", l)
		for k := 0; k < nSlice; k ++ {
			ip2pfx := make(map[string]string)
			pfxCounter := make(map[string]int)
			var ipArray []string
			nowPfxArray := pfxStrArray[k * interval : (k + 1) * interval]
			for j, pfxStr := range nowPfxArray {
				pfxCounter[pfxStr] = 0
				_, pfx, _ := net.ParseCIDR(pfxStr)
				if pfx == nil {
					continue
				}
				pfxBits := utils.Pfx2Bits(pfx)[0]
				if j % 1000 == 999 {
					fmt.Printf("\r%s %d: %d/%d...", outPath, k, j + 1, len(nowPfxArray))
				}
				for i := uint8(0); i < 16; i ++ {
					for {
						newAddr := pfxBits.Copy()
						newAddr.Append(i)
						newAddr.RandFill()
						addrStr := newAddr.ToIPv6()
						if _, ok := ip2pfx[addrStr]; !ok {
							ip2pfx[addrStr] = pfxStr
							ipArray = append(ipArray, addrStr)
							break
						}
					}
				}
			}
			// shuffle
			rand.Shuffle(len(ipArray), func(i, j int) {
				ipArray[i], ipArray[j] = ipArray[j], ipArray[i]
			})
			pp := scanner.NewPingPool(100000, 8, "2001:da8:bf:300:ae1f:6bff:fefb:8924")
			go pp.Run()

			writeStop := false
			go func() {
				for _, ipStr := range ipArray {
					pp.Add(ipStr)
				}
				writeStop = true
			}()
			
			readStop := false
			for {
				if writeStop && !readStop {
					time.Sleep(2 * time.Second)
					readStop = true
				}
				if pp.LenOutChan() == 0 && readStop {
					break
				}
				pendingAddrs := pp.GetAll()
				for _, ipStr := range pendingAddrs {
					pfxCounter[ip2pfx[ipStr]] ++
				}
				time.Sleep(100 * time.Millisecond)
			}

			var aliasPfx []string
			for pfxStr, nRecv := range pfxCounter {
				if nRecv == 16 {
					aliasPfx = append(aliasPfx, pfxStr)
				}
			}
			utils.AppendAddr6ToFS(outPath, aliasPfx)
		}
	}
}

func TestGenScale(t *testing.T) {
	budget := 100000000
	inputFile := "data/2022-04-22-iprdd-1M.txt"
	aliasFile := "data/2022-04-22-aliased-ext.txt"
	fProbes, err := os.Open(inputFile)
	if err != nil {
		panic(err)
	}
	defer fProbes.Close()

	aliasTree := quan.NewAliasTestTree()
	pfxArray := utils.ReadAliasFromFS(aliasFile)
	for _, pfxStr := range pfxArray {
		_, pfx, _ := net.ParseCIDR(pfxStr)
		aliasTree.AddAlias(pfx)
	}

	addrStrArray := utils.ReadAddr6FromFS(inputFile)
	genAlg := _6gen.InitGen(addrStrArray, 4, false)
	probeStrArray := genAlg.GrowClusters(budget, 48)

	pp := scanner.NewPingPool(10000000, 8, "2001:da8:bf:300:ae1f:6bff:fefb:8924")
	go pp.Run()

	nActive := 0
	for i := 0; i < 10; i ++ {
		writeStop := false
		stopCheck := false
		go func() {
			for _, probeStr := range probeStrArray[i * budget / 10 : (i + 1) * budget / 10] {
				pp.Add(probeStr)
			}
			writeStop = true
		}()
		for {
			if writeStop {
				stopCheck = true
				time.Sleep(1900 * time.Millisecond)
			}
			time.Sleep(100 * time.Millisecond)
			if pp.LenOutChan() == 0 && stopCheck {
				break
			}
			if pp.LenOutChan() != 0 {
				for i := 0; i < pp.LenOutChan(); i ++ {
					pp.Get()
					nActive ++
				}
			}
		}
		t.Logf("%d: %.2f\n", i, float64(nActive) / float64((i + 1) * budget / 10) * 100)
	}
}

func TestAliasEntropy(t *testing.T) {
	for pfxLen := uint8(64); pfxLen < 128; pfxLen += 4 {
		pfxLenStr := fmt.Sprintf("%d", pfxLen)
		aliasStrArray := utils.ReadAliasFromFS("data/2022-04-22-aliased.txt")
		aliasArray := make([]utils.BitsArray, 0)
		for _, aliasStr := range aliasStrArray {
			if aliasStr[len(aliasStr) - 2 : ] != pfxLenStr {
				continue
			}
			_, pfx, _ := net.ParseCIDR(aliasStr)
			aliasArray = append(aliasArray, utils.Pfx2Bits(pfx)[0])
		}

		// calculate entropy
		for i := uint8(0); i < pfxLen / 4; i ++ {
			counter := make([]int, 16)
			tot := float64(0)
			for _, aliasBits := range aliasArray {
				counter[aliasBits.IndexAt(i)] ++
				tot ++
			}
			entropy := float64(0)
			for i := range counter {
				if counter[i] == 0 {
					continue
				}
				p := float64(counter[i]) / tot
				entropy -= p * math.Log(p)
			}
			fmt.Printf("%.2f ", entropy)
		}
		fmt.Println()
	}
}

func TestAliasGen(t *testing.T) {
	aliasStrArray := utils.ReadAliasFromFS("data/2022-04-22-aliased.txt")
	fmt.Printf("Read %d alias prefixes from fs.\n", len(aliasStrArray))
	aliasTrie := quan.NewAliasTrie()
	for _, aliasStr := range aliasStrArray {
		_, pfx, _ := net.ParseCIDR(aliasStr)
		aliasTrie.AddPfx(pfx, false)
	}
	aliasStrArray = aliasTrie.GetAliasPfxTD()
	fmt.Printf("Remains %d alias prefixes after filtering.\n", len(aliasStrArray))
	aliasGen := quan.NewAliasGenerator(aliasStrArray, 5)
	genPfxes := aliasGen.Gen()
	utils.SaveAddr6ToFS("test.txt", genPfxes)
}

func TestPfxSize(t *testing.T) {
	pfxStrArray := utils.ReadAliasFromFS("data/2022-04-22-aliased.txt")
	pfxTrie := quan.NewAliasTrie()
	for _, pfxStr := range pfxStrArray {
		_, pfx, _ := net.ParseCIDR(pfxStr)
		if pfx == nil {
			continue
		}
		pfxTrie.AddPfx(pfx, false)
	}
	t.Log(pfxTrie.CountNAddr(true))
}

func TestAPDRecall(t *testing.T) {
	aliasStrArray0 := utils.ReadAliasFromFS("alias/2022-04-22-pfx100-aliased-org0.txt")
	aliasStrArray1 := utils.ReadAliasFromFS("alias/2022-04-22-pfx100-aliased-org1.txt")
	aliasStrArray2 := utils.ReadAliasFromFS("alias/2022-04-22-pfx100-aliased-org2.txt")
	aliasTrie0 := quan.NewAliasTrie()
	aliasTrie1 := quan.NewAliasTrie()
	aliasTrie2 := quan.NewAliasTrie()
	aliasTrie01 := quan.NewAliasTrie()
	aliasTrie12 := quan.NewAliasTrie()
	aliasTrie20 := quan.NewAliasTrie()
	aliasTrie012 := quan.NewAliasTrie()
	for _, aliasStr := range aliasStrArray0 {
		_, pfx, _ := net.ParseCIDR(aliasStr)
		aliasTrie0.AddPfx(pfx, false)
	}
	for _, aliasStr := range aliasStrArray1 {
		_, pfx, _ := net.ParseCIDR(aliasStr)
		aliasTrie1.AddPfx(pfx, false)
	}
	for _, aliasStr := range aliasStrArray2 {
		_, pfx, _ := net.ParseCIDR(aliasStr)
		aliasTrie2.AddPfx(pfx, false)
	}
	for _, aliasStr := range aliasStrArray0 {
		_, pfx, _ := net.ParseCIDR(aliasStr)
		if aliasTrie1.Has(pfx) {
			aliasTrie01.AddPfx(pfx, false)
		}
		if aliasTrie2.Has(pfx) {
			aliasTrie20.AddPfx(pfx, false)
		}
	}
	for _, aliasStr := range aliasStrArray1 {
		_, pfx, _ := net.ParseCIDR(aliasStr)
		if aliasTrie2.Has(pfx) {
			aliasTrie12.AddPfx(pfx, false)
		}
		if aliasTrie0.Has(pfx) {
			aliasTrie01.AddPfx(pfx, false)
		}
	}
	for _, aliasStr := range aliasStrArray2 {
		_, pfx, _ := net.ParseCIDR(aliasStr)
		if aliasTrie0.Has(pfx) {
			aliasTrie20.AddPfx(pfx, false)
		}
		if aliasTrie1.Has(pfx) {
			aliasTrie12.AddPfx(pfx, false)
		}
	}
	for _, aliasStr := range aliasStrArray0 {
		_, pfx, _ := net.ParseCIDR(aliasStr)
		if aliasTrie12.Has(pfx) {
			aliasTrie012.AddPfx(pfx, false)
		}
	}
	for _, aliasStr := range aliasStrArray1 {
		_, pfx, _ := net.ParseCIDR(aliasStr)
		if aliasTrie20.Has(pfx) {
			aliasTrie012.AddPfx(pfx, false)
		}
	}
	for _, aliasStr := range aliasStrArray2 {
		_, pfx, _ := net.ParseCIDR(aliasStr)
		if aliasTrie01.Has(pfx) {
			aliasTrie012.AddPfx(pfx, false)
		}
	}
	count0 := aliasTrie0.CountNAddr(true)
	count1 := aliasTrie1.CountNAddr(true)
	count2 := aliasTrie2.CountNAddr(true)
	count01 := aliasTrie01.CountNAddr(true)
	count12 := aliasTrie12.CountNAddr(true)
	count20 := aliasTrie20.CountNAddr(true)
	count012 := aliasTrie012.CountNAddr(true)
	whole := count0 + count1 + count2 - count01 - count12 - count20 + count012
	fmt.Printf("012: %.2f\n", count012 / whole * 100)
	fmt.Printf("01:  %.2f\n", (count01 - count012) / whole * 100)
	fmt.Printf("12:  %.2f\n", (count12 - count012) / whole * 100)
	fmt.Printf("20:  %.2f\n", (count20 - count012) / whole * 100)
	fmt.Printf("0:   %.2f(%e)\n", (count0 - count01 - count20 + count012) / whole * 1000, count0)
	fmt.Printf("1:   %.2f(%e)\n", (count1 - count12 - count01 + count012) / whole * 1000, count1)
	fmt.Printf("2:   %.2f(%e)\n", (count2 - count20 - count12 + count012) / whole * 1000, count2)
}

func TestAllAlias(t *testing.T) {
	var aliasFiles = [...]string{
		"alias/2022-04-22-pfx10-aliased0.txt",
		"alias/2022-04-22-pfx10-aliased1.txt",
		"alias/2022-04-22-pfx10-aliased2.txt",
		"data/2022-04-22-aliased.txt",
	}
	aliasTrie := quan.NewAliasTrie()
	for _, aliasFile := range aliasFiles {
		for _, aliasStr := range utils.ReadAliasFromFS(aliasFile) {
			_, pfx, _ := net.ParseCIDR(aliasStr)
			aliasTrie.AddPfx(pfx, false)
		}
	}
	t.Log(aliasTrie.CountNAddr(true))
	totAlias := aliasTrie.GetAliasPfx(true)
	utils.SaveAddr6ToFS("alias/2022-04-22-aliased.txt", totAlias)
}

func TestGenResults(t *testing.T) {
	for i := 3; i < 11; i ++ {
		genName := fmt.Sprintf("alias/gen-%d.txt", i)
		resName := fmt.Sprintf("alias/res-%d.txt", i)
		genAliasArray := utils.ReadAliasFromFS(genName)
		resAliasArray := utils.ReadAliasFromFS(resName)
		genTrie := quan.NewAliasTrie()
		resTrie := quan.NewAliasTrie()
		for _, aliasStr := range genAliasArray {
			_, pfx, _ := net.ParseCIDR(aliasStr)
			genTrie.AddPfx(pfx, false)
		}
		for _, aliasStr := range resAliasArray {
			_, pfx, _ := net.ParseCIDR(aliasStr)
			resTrie.AddPfx(pfx, false)
		}
		fmt.Printf("%d,%e,%d,%e\n", len(genAliasArray), genTrie.CountNAddr(true), len(resAliasArray), resTrie.CountNAddr(true))
	}
}
