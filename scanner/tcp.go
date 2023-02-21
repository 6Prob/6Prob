package scanner

import (
	"IPv6/utils"
	"bytes"
	"encoding/binary"
	"net"
	"syscall"
    "time"
)

const (
    IPV6_HDRINCL = 36
    SCAN_LOCAL_PORT = 37492
)

// TCPHeader is a struct that represents a TCP header.
type TCPHeader struct {
	SourcePort      uint16
	DestinationPort uint16
	SeqNumber       uint32
	AckNumber       uint32
	DataOffset      uint8
	Flags           uint8
	WindowSize      uint16
	Checksum        uint16
	UrgentPointer   uint16
}

// IPv6Header is a struct that represents an IPv6 header.
type IPv6Header struct {
    FirstLine uint32
    PayloadLen uint16
    NextHeader uint8
    HopLimit uint8
    Src [16]byte
    Dst [16]byte
}

func (h *IPv6Header) Version() uint32 {
    return h.FirstLine >> 28
}

func (h *IPv6Header) TrafficClass() uint32 {
    return (h.FirstLine >> 20) & 0xff
}

func (h *IPv6Header) FlowLabel() uint32 {
    return h.FirstLine & 0xfffff
}

type TCPool struct {
    inChan       chan string
    outChan      chan string
    localAddrStr string
    remotePort   uint16
    checkSum     uint32
    lastSendTime int64
    sendIntv     int64
}

func NewTCPool(remotePort uint16, bufSize int, localAddrStr string) *TCPool {
    // Pre-calculate checksum in TCP header.
    sum := uint32(0)
    src := net.ParseIP(localAddrStr)
    for i := 0; i < 16; i += 2 {
        sum += uint32(binary.BigEndian.Uint16(src[i : i + 2]))
    }
    sum += syscall.IPPROTO_TCP  // upper layer protocol: TCP
    sum += 20  // TCP length = 20 bytes
    sum += SCAN_LOCAL_PORT
    sum += uint32(remotePort)
    sum += (5 << 12) + 2  // DataOffset | RSV | SYN flag
    sum += 65535  // Window size

    return &TCPool{
        inChan:       make(chan string, bufSize),
        outChan:      make(chan string, bufSize),
        localAddrStr: localAddrStr,
        remotePort:   remotePort,
        checkSum:     sum,
        lastSendTime: 0,
        sendIntv:     0,
    }
}

func (tp *TCPool) Add(addrStr string) {
    tp.inChan <- addrStr
}

func (tp *TCPool) Get() string {
    return utils.GetFullIP(<- tp.outChan)
}

func (tp *TCPool) GetAll() []string {
	var addrStrArray []string
	nOut := len(tp.outChan)
	for i := 0; i < nOut; i ++ {
		addrStrArray = append(addrStrArray, utils.GetFullIP(<- tp.outChan))
	}
	return addrStrArray
}

func (tp *TCPool) Run() {
    go tp.send()
    go tp.recv()
}

func (tp *TCPool) SetPPS(pps int) {
	tp.sendIntv = int64(time.Second) / int64(pps)
}

func (tp *TCPool) checksum(dst [16]byte) uint16 {
    sum := tp.checkSum
    for i := 0; i < 16; i += 2 {
        sum += uint32(binary.BigEndian.Uint16(dst[i : i + 2]))
    }
    return ^uint16((sum >> 16) + (sum & 0xffff))
}

func (tp *TCPool) send() {
    var src, dst [16]byte
    copy(src[:], net.ParseIP(tp.localAddrStr))
    sock, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
    if err != nil {
        panic(err)
    }
    defer syscall.Close(sock)

    // Set the IPV6)HDRINCL option to 1 to include the IPv6 header in the payload.
    if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_IPV6, IPV6_HDRINCL, 1); err != nil {
        panic(err)
    }

    // Create a TCP header.
    tcpHeader := &TCPHeader{
        SourcePort:      SCAN_LOCAL_PORT,
        DestinationPort: tp.remotePort,
        SeqNumber:       0,
        AckNumber:       0,
        DataOffset:      5 << 4,  // DataOffset (4 bits) | RSV (3 bits)
        Flags:           0x02,  // SYN flag
        WindowSize:      65535,
        Checksum:        0,
        UrgentPointer:   0,
    }

    for {
        // Get an address from inChan.
        nowTime := time.Now().UnixNano()
        time.Sleep(time.Duration(tp.lastSendTime + tp.sendIntv - nowTime))
        tp.lastSendTime = nowTime
        remoteHost := <-tp.inChan
        copy(dst[:], net.ParseIP(remoteHost))

        // Create an IPv6 header.
        ipv6Header := &IPv6Header {
            FirstLine:  6 << 28,  // Version (4 bits) | TrafficClass (8 bits) | Flowlabel (20 bits)
            PayloadLen: 20,
            NextHeader: syscall.IPPROTO_TCP,
            HopLimit:   64,
            Src:        src,
            Dst:        dst,
        }

        tcpHeader.Checksum = tp.checksum(dst)
        // Pack the TCP header
        tcpBuf := new(bytes.Buffer)
        if err := binary.Write(tcpBuf, binary.BigEndian, tcpHeader); err != nil {
            panic(err)
        }

        // Pack the IPv6 header.
        ipv6Buf := bytes.NewBuffer(nil)
        if err := binary.Write(ipv6Buf, binary.BigEndian, ipv6Header); err != nil {
            panic(err)
        }

        // Combine the IPv6 header and TCP header into a single buffer.
        packetBuf := make([]byte, ipv6Buf.Len() + tcpBuf.Len())
        copy(packetBuf, ipv6Buf.Bytes())
        copy(packetBuf[ipv6Buf.Len():], tcpBuf.Bytes())

        // Send the packet to the remote host.
        sockaddr := syscall.SockaddrInet6 {
            ZoneId: 0,
            Addr: dst,
        }
        for {
            if err := syscall.Sendto(sock, packetBuf, 0, &sockaddr); err == nil {
                break
            }
        }
    }
}

func (tp *TCPool) recv() {
    sock, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
    if err != nil {
        panic(err)
    }
    defer syscall.Close(sock)

    // Bind with local IPv6 address.
    laddr := &syscall.SockaddrInet6{
        Port: SCAN_LOCAL_PORT,
    }
    copy(laddr.Addr[:], net.ParseIP(tp.localAddrStr))
    err = syscall.Bind(sock, laddr)
    if err != nil {
        panic(err)
    }

    // Read packets.
    for {
        buf := make([]byte, 65535)
        _, addr, err := syscall.Recvfrom(sock, buf, 0)
        if err != nil {
            continue
        }

        // Resolve TCP header.
        remotePort := uint16(buf[0]) << 8 | uint16(buf[1])
        localPort := uint16(buf[2]) << 8 | uint16(buf[3])
        flags := uint8(buf[13])
        // fmt.Println(remotePort)
        if remotePort == tp.remotePort && localPort == SCAN_LOCAL_PORT && flags == 18 {  // 0x1000 (ACK) | 0x10 (SYN) = 18
            remoteIP := net.IP(addr.(*syscall.SockaddrInet6).Addr[:]).String()
            tp.outChan <- remoteIP
        }
    }
}
