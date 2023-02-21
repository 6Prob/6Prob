package quan

import (
	"time"
	"sync"
	"net"

	"IPv6/scanner"
	"IPv6/utils"
)

const (
	maxInterv int64 = 3000
	maxNLost uint8 = 1
)

type AliasStatus struct {
	pfxStr string
	pfxBits utils.BitsArray
	nSent uint8
	nRecv uint8
	lastSent int64
}

func NewAliasStatus(pfxStr string) *AliasStatus {
	_, pfx, _ := net.ParseCIDR(pfxStr)
	return &AliasStatus{
		pfxStr: pfxStr,
		pfxBits: utils.Pfx2Bits(pfx)[0],
		nSent: 0,
		nRecv: 0,
		lastSent: time.Now().UnixMilli(),
	}
}

func (as *AliasStatus) getNext() string {
	scanBits := as.pfxBits.Copy()
	scanBits.Append(as.nSent)
	scanBits.RandFill()
	as.nSent ++
	as.lastSent = time.Now().UnixMilli()
	return scanBits.ToIPv6()
}

func (as *AliasStatus) recvNow() {
	as.nRecv += 1
}

func (as *AliasStatus) allSent() bool {
	return as.nSent == 16
}

func (as *AliasStatus) timeOut() bool {
	return time.Now().UnixMilli() - as.lastSent > maxInterv
}

func (as *AliasStatus) cannotBeAlias() bool {
	return as.nSent - as.nRecv > maxNLost
}

type SimpleAliasDetector struct {
	inChan chan string
	outPfxChan chan string
	outResChan chan bool
	ip2pfx     sync.Map
	sp scanner.ScanPool
	cooldown time.Duration
	outMutex  sync.Mutex
}

func NewSimpleAliasDetector(bufSize int, localAddrStr, protos string) *SimpleAliasDetector {
	return &SimpleAliasDetector{
		inChan: make(chan string, bufSize),
		outPfxChan: make(chan string, bufSize),
		outResChan: make(chan bool, bufSize),
		sp: *scanner.NewScanPool(protos, localAddrStr, bufSize, 1000000),
		cooldown: time.Second,
		outMutex: sync.Mutex{},
	}
}

func (sad *SimpleAliasDetector) Recv() {
	for {
		nowIP := sad.sp.Get()
		nowInterface, ok := sad.ip2pfx.Load(nowIP)
		if ok {
			nowPfx := nowInterface.(*AliasStatus)
			nowPfx.recvNow()
			if nowPfx.allSent() {
				sad.outMutex.Lock()
				sad.outPfxChan <- nowPfx.pfxStr
				sad.outResChan <- true
				sad.outMutex.Unlock()
			} else {
				nextIP := nowPfx.getNext()
				sad.ip2pfx.Store(nextIP, nowPfx)
				sad.sp.Add(nextIP)
			}
			sad.ip2pfx.Delete(nowIP)
		}
	}
}

func (sad *SimpleAliasDetector) Clear() {
	for {
		ipArray := make([]string, 0)
		pfxArray := make([]*AliasStatus, 0)
		sad.ip2pfx.Range(func (key, value interface{}) bool {
			ip := key.(string)
			pfx := value.(*AliasStatus)
			if pfx.timeOut() {
				ipArray = append(ipArray, ip)
				if pfx.cannotBeAlias() {
					pfxArray = append(pfxArray, pfx)
				} else {
					nextIP := pfx.getNext()
					sad.ip2pfx.Store(nextIP, pfx)
					sad.sp.Add(nextIP)
				}
			}
			return true
		})
		for _, ip := range ipArray {
			sad.ip2pfx.Delete(ip)
		}
		for _, pfx := range pfxArray {
			sad.outMutex.Lock()
			sad.outPfxChan <- pfx.pfxStr
			sad.outResChan <- false
			sad.outMutex.Unlock()
		}
	}
}

func (sad *SimpleAliasDetector) Run() {
	go sad.Recv()
	go sad.Clear()
	for {
		nowPfx := NewAliasStatus(<- sad.inChan)
		nowIP := nowPfx.getNext()
		sad.ip2pfx.Store(nowIP, nowPfx)
		sad.sp.Add(nowIP)
	}
}

func (sad *SimpleAliasDetector) Add(nowPfxStr string) {
	sad.inChan <- nowPfxStr
}

func (sad *SimpleAliasDetector) Get() (string, bool) {
	return <-sad.outPfxChan, <-sad.outResChan
}