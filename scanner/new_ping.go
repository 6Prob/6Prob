package scanner

import (
	"IPv6/utils"
	"bytes"
	"encoding/binary"
	"net"
	"syscall"
	"time"
)

type RawPingPool struct {
	inChan       chan string
	outChan      chan string
	localAddrStr string
	checksum     uint32
	lastSendTime int64
	sendIntv     int64
}

func NewRawPingPool(bufSize int, localAddrStr string) *RawPingPool {
	// Pre-calculate checksum in ICMPv6 header.
	sum := uint32(0)
    src := net.ParseIP(localAddrStr)
    for i := 0; i < 16; i += 2 {
        sum += uint32(binary.BigEndian.Uint16(src[i : i + 2]))
    }
    sum += syscall.IPPROTO_ICMPV6  // upper layer protocol: ICMPv6
	sum += 8  // ICMPv6 length
	sum += 0x8000  // type | code

	return &RawPingPool{
		inChan:       make(chan string, bufSize),
		outChan:      make(chan string, bufSize),
		localAddrStr: localAddrStr,
		checksum:     sum,
		lastSendTime: 0,
		sendIntv:     0,
	}
}

func (rpp *RawPingPool) Add(addrStr string) {
	rpp.inChan <- addrStr
}

func (rpp *RawPingPool) Get() string {
	return utils.GetFullIP(<- rpp.outChan)
}

func (rpp *RawPingPool) GetAll() []string {
	var addrStrArray []string
	nOut := len(rpp.outChan)
	for i := 0; i < nOut; i ++ {
		addrStrArray = append(addrStrArray, utils.GetFullIP(<- rpp.outChan))
	}
	return addrStrArray
}

func (rpp *RawPingPool) Run() {
	go rpp.send()
	go rpp.recv()
}

func (rpp *RawPingPool) SetPPS(pps int) {
	rpp.sendIntv = int64(time.Second) / int64(pps)
}

func (rpp *RawPingPool) calChecksum(dst [16]byte) uint16 {
    sum := rpp.checksum
    for i := 0; i < 16; i += 2 {
        sum += uint32(binary.BigEndian.Uint16(dst[i : i + 2]))
    }
    return ^uint16((sum >> 16) + (sum & 0xffff))
}

func (rpp *RawPingPool) send() {
	var src, dst [16]byte
	copy(src[:], net.ParseIP(rpp.localAddrStr))
	// Establish IPv6 raw socket.
    sock, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_ICMPV6)
    if err != nil {
        panic(err)
    }
	defer syscall.Close(sock)

	// Set the IPV6)HDRINCL option to 1 to include the IPv6 header in the payload.
	if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_IPV6, IPV6_HDRINCL, 1); err != nil {
		panic(err)
	}

    // 构造ICMPv6 Echo Request消息
    icmpMsg := []byte{
        // Type: Echo Request
        0x80,
        // Code: 0
        0x00,
        // Checksum
        0x7f, 0xff,
        // id
        0x00, 0x00,
        // seq
        0x00, 0x00,
    }

    // Send ICMPv6 Echo Request message
	for {
		// Get an address from inChan.
		nowTime := time.Now().UnixNano()
		time.Sleep(time.Duration(rpp.lastSendTime + rpp.sendIntv - nowTime))
		rpp.lastSendTime = nowTime
		remoteHost := <-rpp.inChan
		copy(dst[:], net.ParseIP(remoteHost))

		// Create an IPv6 header.
		ipv6Header := &IPv6Header {
            FirstLine:  6 << 28,  // Version (4 bits) | TrafficClass (8 bits) | Flowlabel (20 bits)
            PayloadLen: 8,
            NextHeader: syscall.IPPROTO_ICMPV6,
            HopLimit:   64,
            Src:        src,
            Dst:        dst,
        }
		
		csum := rpp.calChecksum(dst)
		
		icmpMsg[2] = byte(csum >> 8)
		icmpMsg[3] = byte(csum & 0xff)

		ipv6Buf := bytes.NewBuffer(nil)
		if err := binary.Write(ipv6Buf, binary.BigEndian, ipv6Header); err != nil {
			panic(err)
		}

		// Combine the IPv6 header and ICMPv6 into a single buffer.
		packetBuf := make([]byte, ipv6Buf.Len() + len(icmpMsg))
		copy(packetBuf, ipv6Buf.Bytes())
		copy(packetBuf[ipv6Buf.Len():], icmpMsg)

		// Send the packet to the remote host.
		sockaddr := syscall.SockaddrInet6{
			Addr: dst,
		}
		for {
			if err := syscall.Sendto(sock, packetBuf, 0, &sockaddr); err == nil {
				break
			}
		}
	}
}

func (rpp *RawPingPool) recv() {
	sock, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_ICMPV6)
	if err != nil {
		panic(err)
	}
	defer syscall.Close(sock)

	// Set socket option.
	if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_IPV6, syscall.IPV6_RECVPKTINFO, 1); err != nil {
		panic(err)
	}

	buf := make([]byte, 1500)
	for {
		_, _, _, srcAddr, err := syscall.Recvmsg(sock, buf, nil, 0)
		if err != nil {
			continue
		}
		if buf[0] == 0x81 && buf[1] == 0x00 {
			rpp.outChan <- net.IP(srcAddr.(*syscall.SockaddrInet6).Addr[:]).String()
		}
	}
}
