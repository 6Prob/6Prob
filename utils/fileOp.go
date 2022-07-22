package utils

import (
	"os"
	"io"
	"strings"
	"bufio"
	"fmt"
)

func ReadLineAddr6FromFS(filename string) []string {
	var strAddrs []string
	f, err := os.Open(filename)
	if err != nil {
		panic("Open file error.")
	}
	defer f.Close()

	br := bufio.NewReader(f)
	for {
		lineBytes, _, err := br.ReadLine()
		if err == io.EOF {
			break
		}
		strAddrs = append(strAddrs, string(lineBytes))
	}
	return strAddrs
}

func ReadAddr6FromFS(filename string) []string {
	f, err := os.Open(filename)
	if err != nil {
		panic("Open file error.")
	}
	defer f.Close()

	nLines := GetSeedFileNLines(f)
	return ReadAddr6ChunkFromFS(f, 0, nLines)
}

func ReadAddr6ChunkFromFS(f *os.File, start, end int64) []string {
	buf := make([]byte, (Addr6StrLen + 1) * (end - start) - 1)
	f.ReadAt(buf, start * (Addr6StrLen + 1))
	return strings.Split(string(buf), "\n")
}

func ReadAddr6FromFSAt(f *os.File, pos int64) string {
	buf := make([]byte, Addr6StrLen)
	f.ReadAt(buf, pos * (Addr6StrLen + 1))
	return string(buf)
}

func GetSeedFileNLines(f *os.File) int64 {
	fi, err := f.Stat()
	if err != nil {
		panic("Get file info error.")
	}
	return fi.Size() / 40
}

func SearchAddr6FromFS(f *os.File, nLines int64, strAddr string) int64 {
	lo := int64(0)
	hi := nLines
	for lo < hi {
		mi := (lo + hi) >> 1
		if strAddr < ReadAddr6FromFSAt(f, mi) {
			hi = mi
		} else {
			lo = mi + 1
		}
	}
	return lo
}

func SearchPrefix6FromFS(filename, startIP, endIP string) []string {
	// Search addresses located in prefix from file.
	var ipStrArray []string
	
	f, err := os.Open(filename)
	if err != nil {
		panic("Open file error.")
	}
	nLines := GetSeedFileNLines(f)
	startPos := SearchAddr6FromFS(f, nLines, startIP)
	for i := startPos; i < nLines; i ++{
		nowIP := ReadAddr6FromFSAt(f, i)
		if nowIP > endIP {
			break
		} else {
			ipStrArray = append(ipStrArray, nowIP)
		}
	}
	return ipStrArray
}

func ReadPrefixesFromFS(filename string) []string {
	var strPrefixes []string
	f, err := os.Open(filename)
	if err != nil {
		panic("Open file error.")
	}
	defer f.Close()

	buf := bufio.NewReader(f)
	for {
		line, err := buf.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			} else {
				panic("Read file error.")
			}
		}
		seg := strings.Split(line, ",")
		strPrefixes = append(strPrefixes, seg[len(seg) - 2])
	}
	return strPrefixes
}

func ReadAliasFromFS(filename string) []string {
	var strAlias []string
	f, err := os.Open(filename)
	if err != nil {
		panic("Open file error")
	}
	defer f.Close()

	buf := bufio.NewReader(f)
	for {
		line, err := buf.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			} else {
				panic("Read file error.")
			}
		}
		strAlias = append(strAlias, strings.Split(line, "\n")[0])
	}
	return strAlias
}

func SaveAddr6ToFS(filename string, strAddrs []string) {
	os.Remove(filename)
	f, err := os.OpenFile(filename, os.O_CREATE | os.O_WRONLY, 0777)
	if err != nil {
		panic("Create file error.")
	}
	defer f.Close()

	for _, strAddr := range strAddrs {
		f.WriteString(strAddr + "\n")
	}
}

func AppendAddr6ToFS(filename string, strAddrs []string) {
	if _, err := os.Stat(filename); err != nil {
		os.Create(filename)
	} 
	f, err := os.OpenFile(filename, os.O_WRONLY | os.O_APPEND, 0777)
	if err != nil {
		panic("Open file error.")
	}
	defer f.Close()

	strWriting := strings.Join(strAddrs, "\n") + "\n"
	if n, err := f.WriteString(strWriting); err != nil || n != len(strWriting) {
		fmt.Println(err, n, len(strWriting))
	}
}

func Append1Addr6ToFS(filename string, strAddr string) {
	if _, err := os.Stat(filename); err != nil {
		os.Create(filename)
	} 
	f, err := os.OpenFile(filename, os.O_WRONLY | os.O_APPEND, 0777)
	if err != nil {
		panic("Open file error.")
	}
	defer f.Close()

	strWriting := strAddr + "\n"
	if n, err := f.WriteString(strWriting); err != nil || n != len(strWriting) {
		fmt.Println(err, n, len(strWriting))
	}
}