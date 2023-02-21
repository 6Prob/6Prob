package scanner

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

type ScanPool struct {
	nICMP        int
	nTCP         int
	ICMPScanners []*RawPingPool
	TCPScanners  []*TCPool
	addr2Time    sync.Map
	inChan       chan string
	outChan      chan string
}

func NewScanPool(protos, localAddrStr string, bufSize, pps int) *ScanPool {
	sp := &ScanPool{
		inChan:       make(chan string, bufSize),
		outChan:      make(chan string, bufSize),
	}
	go sp.clear()
	var err error
	for _, proto := range strings.Split(protos, ",") {
		if strings.HasPrefix(proto, "ICMP") || strings.HasPrefix(proto, "icmp") {
			if len(sp.ICMPScanners) != 0 {
				panic("Can only specify ICMP once.")
			}
			if len(proto) == 4 {
				sp.nICMP = 1
			} else {
				sp.nICMP, err = strconv.Atoi(proto[4:])
				if err != nil {
					panic(err)
				}
			}
			for i := 0; i < sp.nICMP; i ++ {
				pp := NewRawPingPool(bufSize, localAddrStr)
				pp.Run()
				// Generate a goroutine to constantly hear results from the scanner.
				go func(pp *RawPingPool) {
					for {
						sp.outChan <- pp.Get()
					}
				}(pp)
				sp.ICMPScanners = append(sp.ICMPScanners, pp)
			}
		} else if strings.HasPrefix(proto, "TCP") || strings.HasPrefix(proto, "tcp") {
			sp.nTCP ++
			remotePort, err := strconv.Atoi(proto[3:])
			if err != nil {
				panic(err)
			}
			tp := NewTCPool(uint16(remotePort), bufSize, localAddrStr)
			tp.Run()
			// Generate a goroutine to constantly hear results from the scanner.
			go func(tp *TCPool) {
				for {
					sp.outChan <- tp.Get()
				}
			}(tp)
			sp.TCPScanners = append(sp.TCPScanners, tp)
		} else {
			panic("Invalid protos.")
		}
	}
	pps = pps / (sp.nICMP + sp.nTCP)
	for _, pp := range sp.ICMPScanners {
		pp.SetPPS(pps)
	}
	for _, tp := range sp.TCPScanners {
		tp.SetPPS(pps)
	}
	return sp
}

func (sp *ScanPool) Add(addrStr string) {
	for _, pp := range sp.ICMPScanners {
		pp.Add(addrStr)
	}
	for _, tp := range sp.TCPScanners {
		tp.Add(addrStr)
	}
}

func (sp *ScanPool) Get() string {
	var addrStr string
	for {
		addrStr = <- sp.outChan
		if _, ok := sp.addr2Time.Load(addrStr); ok {
			continue
		} else {
			sp.addr2Time.Store(addrStr, time.Now().UnixNano())
			break
		}
	}
	return addrStr
}

func (sp *ScanPool) GetAll() []string {
	var addrStrArray []string
	nOut := len(sp.outChan)
	for i := 0; i < nOut; i ++ {
		addrStr := <- sp.outChan
		if _, ok := sp.addr2Time.Load(addrStr); ok {
			continue
		} else {
			sp.addr2Time.Store(addrStr, time.Now().UnixNano())
			addrStrArray = append(addrStrArray, addrStr)
		}
	}
	return addrStrArray
}

func (sp *ScanPool) clear() {
	for {
		time.Sleep(time.Second)
		nowTime := time.Now().UnixNano()
		var delArray []string
		sp.addr2Time.Range(func(key, value interface{}) bool {
			if nowTime - value.(int64) > int64(20 * time.Second) {
				delArray = append(delArray, key.(string))
			}
			return true
		})
		for _, delStr := range delArray {
			sp.addr2Time.Delete(delStr)
		}
	}
}

func (sp *ScanPool) LenOutChan() int {
	return len(sp.outChan)
}