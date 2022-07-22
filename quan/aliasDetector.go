package quan

import (
	"time"
	"sync"
	"net"

	"IPv6/scanner"
	"IPv6/utils"
)

type SimpleAliasDetector struct {
	inChan chan string
	outPfxChan chan string
	outResChan chan bool
	resCounter sync.Map
	ip2pfx     sync.Map
	pp scanner.PingPool
	cooldown time.Duration
	outMutex  sync.Mutex
}

func NewSimpleAliasDetector(bufSize int, localAddrStr string) *SimpleAliasDetector {
	return &SimpleAliasDetector{
		inChan: make(chan string, bufSize),
		outPfxChan: make(chan string, bufSize),
		outResChan: make(chan bool, bufSize),
		pp: *scanner.NewPingPool(bufSize, 8, localAddrStr),
		cooldown: time.Second,
		outMutex: sync.Mutex{},
	}
}

func (sad *SimpleAliasDetector) CheckOne(nowPfxStr string) {
	_, nowPfx, _ := net.ParseCIDR(nowPfxStr)
	nowPfxBits := utils.Pfx2Bits(nowPfx)[0]
	sad.resCounter.Store(nowPfxStr, false)
	isAlias := true
	ipArray := make([]string, 0)
	nMiss := 0
	for i := uint8(0); i < 16; i ++ {
		scanBits := nowPfxBits.Copy()
		scanBits.Append(i)
		scanBits.RandFill()
		scanIP := scanBits.ToIPv6()
		ipArray = append(ipArray, scanIP)
		sad.ip2pfx.Store(scanIP, nowPfxStr)
		sad.pp.Add(scanIP)
		active := false
		for j := 0; j < 10; j ++ {
			time.Sleep(sad.cooldown / 10)
			if res, _ := sad.resCounter.Load(nowPfxStr); res == false {
				continue
			} else {
				active = true
				break
			}
		}
		if active {
			sad.resCounter.Store(nowPfxStr, false)
		} else {
			nMiss ++
			if nMiss == 2 {
				isAlias = false
				break
			}
		}
	}

	// output
	sad.outMutex.Lock()
	sad.outPfxChan <- nowPfxStr
	if isAlias {
		sad.outResChan <- true
	} else {
		sad.outResChan <- false
	}
	sad.outMutex.Unlock()

	// clear
	for _, ip := range ipArray {
		sad.ip2pfx.Delete(ip)
	}
	sad.resCounter.Delete(nowPfxStr)
}

func (sad *SimpleAliasDetector) Recv() {
	for {
		nowIP := sad.pp.Get()
		nowPfxStr, _ := sad.ip2pfx.Load(nowIP)
		sad.resCounter.Store(nowPfxStr, true)
	}
}

func (sad *SimpleAliasDetector) Run() {
	go sad.pp.Run()
	go sad.Recv()
	for {
		nowPfxStr := <- sad.inChan
		go sad.CheckOne(nowPfxStr)
	}
}

func (sad *SimpleAliasDetector) Add(nowPfxStr string) {
	sad.inChan <- nowPfxStr
}

func (sad *SimpleAliasDetector) Get() (string, bool) {
	return <-sad.outPfxChan, <-sad.outResChan
}