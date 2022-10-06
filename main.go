package main

import (
	"IPv6/quan"
	"IPv6/scanner"
	"IPv6/utils"
	"IPv6/_6gen"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
	"time"
	"strings"
	"strconv"
	"sync"
)

const (
	rate int64 = 100000
)

var (
	module = flag.String("module", "", "std|scan|shuffle|sort|alias|gen. All operations need standard form except std!!!")
	inputFile = flag.String("input", "", "The file need processing")
	outputFile = flag.String("output", "", "The output path of results")
	nProc = flag.Int("n-proc", 1, "# thread used in 6Prob generation")
	budget = flag.Int("budget", 1000000, "# probe used in 6Prob generation")
	aliasFile = flag.String("alias", "data/2022-04-07-aliased.txt", "Detected alias prefixes")
	outAliasFile = flag.String("out-alias", "", "Output path for newly-detected alias prefixes during scanning of 6Prob")
	sourceIP  = flag.String("source-ip", "", "The source IP used for scanning")
	nScanProc = flag.Int("n-scan-proc", 8, "# thread used for sending ICMP request message")
	dealias = flag.Bool("dealias", true, "whether dealias during 6Prob generation")
	thres = flag.Int("thres", 4, "threshold between clusters / threshold of get prefixes from seed addresses")
)

func std(inputFile, outputFile string) {
	// transform addresses in inputFile to standard form
	fmt.Println("Loading addresses to memory...")
	addrStrArray := utils.ReadLineAddr6FromFS(inputFile)
	outStrArray := make([]string, len(addrStrArray))
	for i, addrStr := range addrStrArray {
		if i % 100000 == 0 {
			fmt.Printf("\r%d/%d addresses transformed...", i + 1, len(addrStrArray))
		}
		addr := net.ParseIP(addrStr)
		addrBits := utils.NewBitsArray(32, []byte(addr))
		outStrArray[i] = addrBits.ToIPv6()
		if outStrArray[i] == "0000:0000:0000:0000:0000:0000:0000:0000" {
			fmt.Println("addrStr", len(addrStr))
			fmt.Println("addr", addr)
			panic("")
		}
	}
	fmt.Println("Saving standardized results to FS...")
	utils.SaveAddr6ToFS(outputFile, outStrArray)
}

func scan(sourceIP, inputFile, outputFile string, nScanProc int) {
	// scan all addresses in inputFile like zmap
	fProbes, err := os.Open(inputFile)
	if err != nil {
		fmt.Println(err)
	}
	defer fProbes.Close()
	addrArray := utils.ReadLineAddr6FromFS(inputFile)
	nProbeLines := len(addrArray)
	fmt.Printf("Start scanning %d addresses...\n", nProbeLines)
	pp := scanner.NewPingPool(100000, nScanProc, sourceIP)
	nActive := 0
	writeStop := false
	go pp.Run()
	// write to PingPool
	go func() {
		startTime := time.Now().Unix()
		for i, addrStr := range addrArray {
			if i % 10 == 0 || i == nProbeLines - 1 {
				// statistics
				completeRatio := float64(i) / float64(nProbeLines)
				activeRatio := float64(nActive) / float64(i)
				nowTime := time.Now().Unix()
				second := nowTime - startTime
				remainSecond := int64(float64(second) / completeRatio) - second
				hour := second / 3600
				second %= 3600
				minute := second / 60
				second %= 60
				remainHour := remainSecond / 3600
				remainSecond %= 3600
				remainMinute := remainSecond / 60
				remainSecond %= 60
				fmt.Printf("\r[%02d:%02d:%02d] Probe: Sending addresses %.2f%%; hitrate: %.2f%%; %02d:%02d:%02d remaining...", hour, minute, second, completeRatio * 100, activeRatio * 100, remainHour, remainMinute, remainSecond)
			}
			pp.Add(addrStr)
		}
		fmt.Println("\nAll probes are sent! Waiting final responses for 2 seconds...")
		writeStop = true
	}()
	// read
	os.Remove(outputFile)
	stopCheck := false
	for {
		if writeStop && !stopCheck {
			stopCheck = true
			time.Sleep(2 * time.Second)
		}
		time.Sleep(time.Second)
		outStrArray := pp.GetAll()
		if len(outStrArray) == 0 {
			if stopCheck {
				break
			} else {
				continue
			}
		} else {
			nActive += len(outStrArray)
		}
		utils.AppendAddr6ToFS(outputFile, outStrArray)
	}
}

func shuffle(inputFile, outputFile string) {
	fmt.Println("Loading addresses to memory...")
	addrStrArray := utils.ReadAddr6FromFS(inputFile)
	fmt.Println("Shuffling...")
	rand.Shuffle(len(addrStrArray), func(i, j int) {
		addrStrArray[i], addrStrArray[j] = addrStrArray[j], addrStrArray[i]
	})
	fmt.Println("Saving shuffled results to FS...")
	utils.SaveAddr6ToFS(outputFile, addrStrArray)
}

func _sort(inputFile, outputFile string) {
	fmt.Println("Loading addresses to memory...")
	addrStrArray := utils.ReadAddr6FromFS(inputFile)
	fmt.Println("Sorting...")
	sort.Strings(addrStrArray)
	fmt.Println("Saving sorted results to FS...")
	utils.SaveAddr6ToFS(outputFile, addrStrArray)
}

func filAlias(inputFile, aliasFile, outputFile string) {
	fmt.Println("Loading alias trie...")
	aliasTrie := quan.NewAliasTestTree()
	strAliasArray := utils.ReadAliasFromFS(aliasFile)
	for _, strAlias := range strAliasArray {
		_, pfx, _ := net.ParseCIDR(strAlias)
		aliasTrie.AddAlias(pfx)
	}
	fmt.Println("Loading addresses to memory...")
	addrStrArray := utils.ReadLineAddr6FromFS(inputFile)
	nAddrLines := len(addrStrArray)
	var deaStrArray []string
	for i, addrStr := range addrStrArray {
		if i % 100000 == 0 {
			fmt.Printf("\r%.2f%% checking...", float64(i + 1) / float64(nAddrLines) * 100)
		}
		addr := net.ParseIP(addrStr)
		if !aliasTrie.IsAlias(addr) {
			deaStrArray = append(deaStrArray, addrStr)
		}
	}
	fmt.Printf("Writing %d dealiased results to FS..\n", len(deaStrArray))
	utils.SaveAddr6ToFS(outputFile, deaStrArray)
}

func gen(sourceIP, inputFile, outputFile, aliasFile, outAliasFile string, nProc, nScanProc, budget int, dealias bool) {
	fmt.Println("New Version")
	genInterval := 1000000 / rate
	startTime := time.Now().Unix()
	fmt.Printf("Seed is %d\n", startTime)
	rand.Seed(startTime)
	pTree := quan.NewProbTree()
	fProbes, err := os.Open(inputFile)
	if err != nil {
		panic(err)
	}
	defer fProbes.Close()
	aliasOutFile := outputFile[:len(outputFile) - 4] + "-alias.txt"
	os.Remove(aliasOutFile)
	os.Remove(outputFile)
	if outAliasFile != "" {
		os.Remove(outAliasFile)
	}

	// init alias tree
	fmt.Println("Loading alias prefixes...")
	aliasTree := quan.NewAliasTestTree()
	pfxArray := utils.ReadAliasFromFS(aliasFile)
	for _, pfxStr := range pfxArray {
		_, pfx, _ := net.ParseCIDR(pfxStr)
		aliasTree.AddAlias(pfx)
	}

	// init alias detector
	aliasDet := quan.NewSimpleAliasDetector(100, sourceIP)
	go aliasDet.Run()

	// start probing goroutines
	pp := scanner.NewPingPool(100000000, nScanProc, sourceIP)
	realtimeAPD := quan.NewSimpleAliasDetector(100000, sourceIP)
	go pp.Run()
	go realtimeAPD.Run()
	nActive := 0
	nProbe := 0
	nMayBeAlias := 0
	nAlias := 0
	nUnderAPD := 0
	detectedPfx := sync.Map{}
	aliasDict := sync.Map{}
	// aliasDict := make(map[string][][]*quan.ProbNode)

	// start statistics and save goroutine
	before := 0
	outChan := make(chan string, 100000)
	writeStop := false
	stopCheck := false
	finalStop := false
	go func() {
		for {
			if writeStop && !stopCheck {
				stopCheck = true
				time.Sleep(2 * time.Second)
			}
			time.Sleep(time.Second)
			activeRatio := float64(nActive) / float64(nProbe) * 100
			nowTime := time.Now().Unix()
			second := nowTime - startTime
			hour := second / 3600
			second %= 3600
			minute := second / 60
			second %= 60
			fmt.Printf("\r[%02d:%02d:%02d] %d addresses generated. Now active ratio %.2f%%(%.2f%%). Now alias ratio %d/%d. %d is now under APD...", hour, minute, second, nProbe, activeRatio, pTree.GetEstimation(), nAlias, nMayBeAlias, nUnderAPD)
			// pTree.PrintInfo()
			after := nProbe % 10000000
			if after < before {
				fmt.Println()
			}
			before = after
			var pendingAddrs []string
			if len(outChan) == 0 && stopCheck {
				finalStop = true
				break
			}
			if len(outChan) > 0 {
				for i := 0; i < len(outChan); i ++ {
					pendingAddrs = append(pendingAddrs, <-outChan)
				}
				utils.AppendAddr6ToFS(outputFile, pendingAddrs)
			}
		}
	}()

	// initialize the tree
	fmt.Println("Initialize 6Prob model with seed addresses...")
	ipStrArray := utils.ReadAddr6FromFS(inputFile)
	pTree.Init(ipStrArray)
	fmt.Println("Done.")
	for _, ipStr := range ipStrArray {
		pp.Add(ipStr)
	}
	nProbe += len(ipStrArray)
	time.Sleep(2 * time.Second)

	// initialize the trie with pre-scan addresses
	for pp.LenOutChan() != 0 {
		outStr := pp.Get()
		nActive ++
		pTree.AddActive(net.ParseIP(outStr))
		outChan <- outStr
	}

	pTree.PrintInfo()

	// realtime apd goroutine
	go func(){
		for {
			pfxStr, isAlias := realtimeAPD.Get()
			detectedPfx.Store(pfxStr, isAlias)
			if isAlias {
				nAlias ++
			}
			prefixLen, _ := strconv.Atoi(strings.Split(pfxStr, "/")[1])
			paths, _ := aliasDict.Load(pfxStr)
			aliasDict.Delete(pfxStr)
			nUnderAPD --
			for _, nodesOnPath := range paths.([][]*quan.ProbNode) {
				pTree.AddAlias(nodesOnPath, isAlias, uint8(prefixLen))
			}
			if outAliasFile != "" {
				if isAlias {
					utils.Append1Addr6ToFS(outAliasFile, pfxStr)
				}
			}
		}
	}()

	// response goroutines
	for i := 0; i < nProc; i ++ {
		go func(){
			for {
				outStr := pp.Get()
				nActive ++
				pTree.AddActive(net.ParseIP(outStr))
				outChan <- outStr
			}
		}()
	}

	// start probing system
	go pp.Run()
	for i := 0; i < nProc; i ++ {
		go func(){
			for {
				startTime := time.Now().UnixMicro()
				if nProbe == budget {
					writeStop = true
					break
				}
				nProbe ++
				newAddrStr, nodesOnPath := pTree.Generate()
				if find := strings.Contains(newAddrStr, "/"); find {
					if isAlias, ok := detectedPfx.Load(newAddrStr); ok {
						prefixLen, _ := strconv.Atoi(strings.Split(newAddrStr, "/")[1])
						pTree.AddAlias(nodesOnPath, isAlias.(bool), uint8(prefixLen))
					} else {
						paths, ok := aliasDict.Load(newAddrStr)
						if !ok {
							nUnderAPD ++
							realtimeAPD.Add(newAddrStr)
							nMayBeAlias ++
							newPaths := make([][]*quan.ProbNode, 1)
							newPaths[0] = nodesOnPath
							aliasDict.Store(newAddrStr, newPaths)
						} else {
							aliasDict.Store(newAddrStr, append(paths.([][]*quan.ProbNode), nodesOnPath))
						}
					}
				} else if !aliasTree.IsAlias(net.ParseIP(newAddrStr)) {
					pp.Add(newAddrStr)
					endTime := time.Now().UnixMicro()
					usedTime := endTime - startTime
					if usedTime < genInterval {
						time.Sleep(time.Duration(genInterval - usedTime) * time.Microsecond)
					}
				}
			}
		}()
	}

	// wait other goroutines to stop
	for {
		if finalStop {
			break
		}
		time.Sleep(5 * time.Second)
	}
}

func detAlias(sourceIP, inputFile, outputFile string, nScanProc int) {
	nowTime := time.Now().UnixNano()
	fmt.Printf("Seed is %d\n", nowTime)
	rand.Seed(nowTime)
	candPfxArray := utils.ReadAliasFromFS(inputFile)

	aTrie := quan.NewAliasTrie()
	startTime := time.Now().Unix()
	fmt.Println("Initialize alias tree...")
	for i, pfxStr := range candPfxArray {
		if (i + 1) % 10000 == 0 || i + 1 == len(candPfxArray) {
			nowTime := time.Now().Unix()
			second := nowTime - startTime
			hour := second / 3600
			second %= 3600
			minute := second / 60
			second %= 60
			fmt.Printf("\r[%02d:%02d:%02d] Probe: Reading addresses %.2f%%...", hour, minute, second, float64(i + 1) / float64(len(candPfxArray)) * 100)
		}
		_, pfx, _ := net.ParseCIDR(pfxStr)
		aTrie.AddPfx(pfx, false)
	}
	fmt.Println("Done.")

	// start probing system
	pp := scanner.NewPingPool(100000, nScanProc, sourceIP)
	writeStop := false
	nProbes := 0
	pfxSet := make(map[string]bool)
	go pp.Run()
	go func() {
		for {
			newAddrStr, pfxStr := aTrie.GenerateTopDown()
			nProbes ++
			pfxSet[pfxStr] = true
			if newAddrStr == "" {
				writeStop = true
				break
			}
			pp.Add(newAddrStr)
		}
		fmt.Println(len(pfxSet), len(candPfxArray))
	}()
	go func() {
		for {
			outStr := pp.Get()
			aTrie.AddActiveTopDown(net.ParseIP(outStr))
		}
	}()
	for !writeStop {
		nowTime := time.Now().Unix()
		second := nowTime - startTime
		hour := second / 3600
		second %= 3600
		minute := second / 60
		second %= 60
		fmt.Printf("\r[%02d:%02d:%02d] #probes: %d; #pfx: %d/%d", hour, minute, second, nProbes, len(pfxSet), len(candPfxArray))
		time.Sleep(time.Second)
	}
	pfxArray := aTrie.GetAliasPfxTD()
	utils.SaveAddr6ToFS(outputFile, pfxArray)
	fmt.Printf("#alias prefixes: %d; #alias addresses: %.2E.\n", len(pfxArray), aTrie.CountNAddr(false))
}

func dealiasScan(sourceIP, inputFile, outputFile, aliasFile string, nScanProc int) {
	// dealiasScan will ignore addresses in alias region
	// init alias tree
	aliasTrie := quan.NewAliasTestTree()
	pfxArray := utils.ReadAliasFromFS(aliasFile)
	for _, pfxStr := range pfxArray {
		_, pfx, _ := net.ParseCIDR(pfxStr)
		aliasTrie.AddAlias(pfx)
	}

	// scan all addresses in inputFile like zmap
	fProbes, err := os.Open(inputFile)
	if err != nil {
		fmt.Println(err)
	}
	defer fProbes.Close()
	addrArray := utils.ReadLineAddr6FromFS(inputFile)
	nProbeLines := len(addrArray)
	fmt.Printf("Start scanning %d addresses...\n", nProbeLines)
	pp := scanner.NewPingPool(100000, nScanProc, sourceIP)
	nActive := 0
	writeStop := false
	go pp.Run()
	// write to PingPool
	go func() {
		startTime := time.Now().Unix()
		for i, addrStr := range addrArray {
			if i % 100000 == 0 || i == nProbeLines - 1 {
				// statistics
				completeRatio := float64(i) / float64(nProbeLines)
				activeRatio := float64(nActive) / float64(i)
				nowTime := time.Now().Unix()
				second := nowTime - startTime
				remainSecond := int64(float64(second) / completeRatio) - second
				hour := second / 3600
				second %= 3600
				minute := second / 60
				second %= 60
				remainHour := remainSecond / 3600
				remainSecond %= 3600
				remainMinute := remainSecond / 60
				remainSecond %= 60
				fmt.Printf("\r[%02d:%02d:%02d] Probe: Sending addresses %.2f%%; hitrate: %.2f%%; %02d:%02d:%02d remaining...", hour, minute, second, completeRatio * 100, activeRatio * 100, remainHour, remainMinute, remainSecond)
			}
			if !aliasTrie.IsAlias(net.ParseIP(addrStr)) {
				pp.Add(addrStr)
			}
		}
		fmt.Println("\nAll probes are sent! Waiting final responses for 2 seconds...")
		writeStop = true
	}()
	// read
	os.Remove(outputFile)
	os.Create(outputFile)
	stopCheck := false
	for {
		if writeStop && !stopCheck {
			stopCheck = true
			time.Sleep(2 * time.Second)
		}
		time.Sleep(time.Second)
		outStrArray := pp.GetAll()
		if len(outStrArray) == 0 {
			if stopCheck {
				break
			} else {
				continue
			}
		} else {
			nActive += len(outStrArray)
		}
		utils.AppendAddr6ToFS(outputFile, outStrArray)
	}
}

func gen6(sourceIP, inputFile, outputFile, aliasFile string, nProc, nScanProc, budget int) {
	startTime := time.Now().Unix()
	fmt.Printf("Seed is %d\n", startTime)
	rand.Seed(startTime)
	fProbes, err := os.Open(inputFile)
	if err != nil {
		panic(err)
	}
	defer fProbes.Close()
	os.Remove(outputFile)

	// init alias tree
	aliasTree := quan.NewAliasTestTree()
	pfxArray := utils.ReadAliasFromFS(aliasFile)
	for _, pfxStr := range pfxArray {
		_, pfx, _ := net.ParseCIDR(pfxStr)
		aliasTree.AddAlias(pfx)
	}

	// use 6Gen to generate new addresses
	addrStrArray := utils.ReadAddr6FromFS(inputFile)
	genAlg := _6gen.InitGen(addrStrArray, 4, false)
	probeStrArray := genAlg.GrowClusters(budget, nProc)

	// probe new addresses
	pp := scanner.NewPingPool(100000000, nScanProc, sourceIP)
	go pp.Run()

	writeStop := false
	stopCheck := false
	nProbe := 0
	nActive := 0
	go func() {
		for _, probeStr := range probeStrArray {
			pp.Add(probeStr)
			nProbe ++
		}
		writeStop = true
	}()
	
	for {
		if writeStop {
			stopCheck = true
		}
		time.Sleep(time.Second)
		activeRatio := float64(nActive) / float64(nProbe)
		nowTime := time.Now().Unix()
		second := nowTime - startTime
		hour := second / 3600
		second %= 3600
		minute := second / 60
		second %= 60
		fmt.Printf("\r[%02d:%02d:%02d] %d addresses generated. Now active ratio %.2f %%...", hour, minute, second, nProbe, activeRatio)
		var pendingAddrs []string
		if pp.LenOutChan() == 0 && stopCheck {
			break
		}
		if pp.LenOutChan() != 0 {
			for i := 0; i < pp.LenOutChan(); i ++ {
				pendingAddrs = append(pendingAddrs, pp.Get())
			}
			utils.AppendAddr6ToFS(outputFile, pendingAddrs)
		}
	}
}

func getPfx(inputFile, outputFile string, thres int) {
	os.Remove(outputFile)
	qTrie := quan.NewQuanTrie(false)
	fInput, err := os.Open(inputFile)
	if err != nil {
		panic(err)
	}
	defer fInput.Close()

	nowPfx := utils.ReadAddr6FromFSAt(fInput, 0)[:20]
	nPfx := 0
	nSeedLines := utils.GetSeedFileNLines(fInput)
	for i := int64(0); i < nSeedLines; i ++ {
		if (i + 1) % 100000 == 0 || i == nSeedLines - 1 {
			fmt.Printf("\r%.2f%% adding, now %d prefixes detected...", float32(i + 1) / float32(nSeedLines) * 100, nPfx)
		}
		ipStr := utils.ReadAddr6FromFSAt(fInput, i)
		pfxStr := ipStr[:20]
		if pfxStr != nowPfx {
			pfxStrArray := qTrie.GetValuablePfx(uint32(thres))
			if len(pfxStrArray) != 0 {
				utils.AppendAddr6ToFS(outputFile, pfxStrArray)
			}
			nowPfx = pfxStr
			qTrie = quan.NewQuanTrie(false)
			nPfx += len(pfxStrArray)
		}
		qTrie.Add(net.ParseIP(ipStr), true, true)
	}
	pfxStrArray := qTrie.GetValuablePfx(uint32(thres))
	if len(pfxStrArray) != 0 {
		utils.AppendAddr6ToFS(outputFile, pfxStrArray)
	}
	fmt.Println("Done.")
}

func genAlias(inputFile, outputFile string, thres int) {
	aliasStrArray := utils.ReadAliasFromFS(inputFile)
	fmt.Printf("Read %d alias prefixes from fs.\n", len(aliasStrArray))
	fmt.Println("Filtering...")
	aliasTrie := quan.NewAliasTrie()
	for _, aliasStr := range aliasStrArray {
		_, pfx, _ := net.ParseCIDR(aliasStr)
		aliasTrie.AddPfx(pfx, false)
	}
	aliasStrArray = aliasTrie.GetAliasPfxTD()
	fmt.Printf("Remains %d alias prefixes after filtering.\n", len(aliasStrArray))
	aliasGen := quan.NewAliasGenerator(aliasStrArray, thres)
	genPfxes := aliasGen.Gen()
	utils.SaveAddr6ToFS(outputFile, genPfxes)
}

func main() {
	flag.Parse()
	switch *module {
	case "std":
		std(*inputFile, *outputFile)
	case "scan":
		scan(*sourceIP, *inputFile, *outputFile, *nScanProc)
	case "shuffle":
		shuffle(*inputFile, *outputFile)
	case "sort":
		_sort(*inputFile, *outputFile)
	case "filAlias":
		filAlias(*inputFile, *aliasFile, *outputFile)
	case "gen":
		gen(*sourceIP, *inputFile, *outputFile, *aliasFile, *outAliasFile, *nProc, *nScanProc, *budget, *dealias)
	case "detAlias":
		detAlias(*sourceIP, *inputFile, *outputFile, *nScanProc)
	case "dealiasScan":
		dealiasScan(*sourceIP, *inputFile, *outputFile, *aliasFile, *nScanProc)
	case "6gen":
		gen6(*sourceIP, *inputFile, *outputFile, *aliasFile, *nProc, *nScanProc, *budget)
	case "getPfx":
		getPfx(*inputFile, *outputFile, *thres)
	case "genAlias":
		genAlias(*inputFile, *outputFile, *thres)
	}
}