# 6Prob: A Probabilistic IPv6 Generation Model for Efficient Internet-wide Address Scanning

### Abstract
Active IPv6 address scanning is the foundation of many other security and measurement research works. However, IPv6 address space is too large to enumerate in a reasonable time. Due to the large scale of IPv6 addresses, researchers try to use known active IPv6 addresses (the IPv6 Hitlist) as heuristics to find new addresses. State-of-the-art algorithms suffer from poor scalability to the growing IPv6 Hitlist and limited ability to find active addresses, resulting in not capable of the Internet-wide IPv6 scanning. In this paper, we have made two contributions. First, we dig into the alias prefix problem, which can hugely affect the generation performance, to get a more reliable and powerful detector for alias prefixes. This detector consists of cool-down detection to alleviate saturation scanning and a generator to discover new alias prefixes based on the known. Second, We propose a probabilistic IPv6 generation model, 6Prob, to generate new IPv6 addresses efficiently. 6Prob not only improves generation ability by at least 84\% or 144\% with different seed sets but also decrease the usage of time and space to a much more reasonable amount compared to previous works. These critical improvements make 6Prob ready for efficient Internet-wide address scanning.

### Compile
go version go1.17.5

Build executable file `6prob` by

```
go build -o 6prob
```

or you can directly run from source by

```
go run main.go -h
```

### Usage
```
6prob -module=std -input=<input file> -output=<output file>
```
> Module `std` is used to standardize addresses to the form with no abbreviation. (2402:123::1 => 2402:0123:0000:0000:0000:0000:0000:0001).

```
6prob -module=scan -input=<input file> -output=<output file> [-source-ip=<source IP> -n-scan-proc=<# scan processes>]
```
> Module `scan` is used to scan addresses in the input file and output active addresses to the output file.

```
6prob -module=shuffle -input=<input file> -output=<output file>
```
> Module `shuffle` is used to randomly premute the address in the input file and output results to the output file.

```
6prob -module=sort -input=<input file> -output=<output file>
```
> Module `sort` is used to sort addresses in the input file in the Lexicographic order and output results to the output file.

```
6prob -module=filAlias -input=<input file> -output=<output file> -alias=<alias file>
```
> Module `filAlias` is used to filter addresses in the input file with alias prefixes in the alias file and output results to the output file.

```
6prob -module=gen -input=<input file> -output=<output file> -alias=<alias file> -budget=<# generated addresses> [-source-ip=<source IP> -n-proc=<# processes for generating and updating> -n-scan-proc=<# scan processes>]
```
> Module `gen` uses 6Prob model to generate new addresses based on addresses in the input file. Alias file is used to prevent model generating alias addresses. Budget is the number of generated addresses you want.

```
6prob -module=detAlias -input=<input file> -output=<output file> [-source-ip=<source IP> -n-scan-proc=<# scan processes>]
```
> Module `detAlias` uses cool-down detection for alias prefixes to detect alias prefixes in the input file and output them to the output file.

```
6prob -module=dealiasScan -input=<input file> -output=<output file> -alias=<alias file> [-source-ip=<source IP> -n-scan-proc=<# scan processes>]
```
> Module `dealiasScan` is used to scan addresses in the input file but ignore aliased addresses covered by ailas prefixes in the alias file.

```
6prob -module=6gen -input=<input file> -output=<output file> -alias=<alias file> -budget=<# generated addresses> [-source-ip=<source IP> -n-proc=<# processes for initialization> -n-scan-proc=<# scan processes>]
```
> Module `6gen` uses 6Gen to generate new addresses based on addresses in the input file.

```
6prob -module=getPfx -input=<input file> -output=<output file> -thres=<# hosts>
```
> Module `getPfx` gets prefixes with more than thres hosts presented in the input file and output results to output file.

```
6prob -module=genAlias -input=<input file> -output=<output file> -thres=<threshold distance>
```
> Module `genAlias` generates new alias prefixes based on ones in the input file with the threshold distance.














