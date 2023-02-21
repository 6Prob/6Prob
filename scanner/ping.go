package scanner

import (
	"IPv6/utils"
	"fmt"
	"net"
	"time"

	"sync"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

type PingPool struct {
	inChan    chan string
	outChan   chan string
	bufChan   chan []byte
	addrChan  chan net.Addr
	lisConn   *net.IPConn
	addr2Time sync.Map
	tMax      int
	msg       []byte
}

func NewPingPool(bufSize, tMax int, localAddrStr string) *PingPool {
	localAddr, err := net.ResolveIPAddr("ip6", localAddrStr)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	conn, err := net.ListenIP("ip6:ipv6-icmp", localAddr)
	if err != nil {
		fmt.Println(err)
	}

	// packet construction
	msg := make([]byte, 8)
	msg[0] = 128  // icmpv6 echo requset type
	msg[1] = 0    // icmpv6 echo request code
	msg[2] = 127
	msg[3] = 255
	msg[4] = 0  // id[0]
	msg[5] = 0  // id[1]
	msg[6] = 0  // id[2]
	msg[7] = 0  // id[3]
	
	return &PingPool{
		inChan:   make(chan string, bufSize),
		outChan:  make(chan string, bufSize),
		bufChan:  make(chan []byte, bufSize),
		addrChan: make(chan net.Addr, bufSize),
		lisConn:  conn,
		tMax:     tMax,
		msg:      msg,
	}
}

func (pp *PingPool) Add(addrStr string) {
	pp.inChan <- addrStr
}

func (pp *PingPool) clear() {
	// clear out-dated map infomation periodically
	for {
		time.Sleep(time.Second)
		nowTime := time.Now().UnixNano()
		var delArray []string
		pp.addr2Time.Range(func(key, value interface{}) bool {
			if nowTime - value.(int64) > int64(20 * time.Second) {
				delArray = append(delArray, key.(string))
			}
			return true
		})
		for _, delStr := range delArray {
			pp.addr2Time.Delete(delStr)
		}
	}
}

func (pp *PingPool) recv() {
	for {
		buf := make([]byte, 8)
		_, addr, err := pp.lisConn.ReadFrom(buf)
		if err != nil {
			fmt.Println(err)
		}
		pp.bufChan <- buf
		pp.addrChan <- addr
	}
}

func (pp *PingPool) procMsg() {
	for {
		buf  := <- pp.bufChan
		addr := <- pp.addrChan
		msg, _ := icmp.ParseMessage(58, buf)
		addrStr := addr.String()
		if msg.Type == ipv6.ICMPTypeEchoReply {
			if _, ok := pp.addr2Time.Load(addrStr); ok {
				pp.outChan <- addrStr
				pp.addr2Time.Delete(addrStr)
			}
		}
	}
}

func (pp *PingPool) send() {
	for {
		addrStr := <- pp.inChan
		remoteAddr, err := net.ResolveIPAddr("ip6", addrStr)
		if err != nil {
			fmt.Println(err)
		}
		conn, err := net.DialIP("ip6:ipv6-icmp", nil, remoteAddr)
		if err != nil {
			continue
		}
		if _, err := conn.Write(pp.msg); err != nil {
			continue
		}
		pp.addr2Time.Store(remoteAddr.String(), time.Now().UnixNano())
		conn.Close()
	}
}

func (pp *PingPool) Run() {
	// start clear gorouting
	go pp.clear()
	// start listen gorouting
	go pp.recv()
	// start proc gorouting
	go pp.procMsg()
	// start clear gorouting
	go pp.clear()
	// start probing gorouting
	for i := 0; i < pp.tMax; i ++ {
		go pp.send()
	}
}

func (pp *PingPool) Get() string {
	return utils.GetFullIP(<- pp.outChan)
}

func (pp *PingPool) GetAll() []string {
	var addrStrArray []string
	nOut := len(pp.outChan)
	for i := 0; i < nOut; i ++ {
		addrStrArray = append(addrStrArray, utils.GetFullIP(<- pp.outChan))
	}
	return addrStrArray
}

func (pp *PingPool) LenOutChan() int {
	return len(pp.outChan)
}
