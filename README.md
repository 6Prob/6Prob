# 6Prob: Efficient and Dealiased Discovery of Active IPv6 Addresses

### Abstract
With the rapid growth of IPv6 deployment, active IPv6 address discovery has become the foundation of Internet security and measurement research. Unfortunately, the vast IPv6 address space makes brute force scanning used in IPv4 impractical. Today, a common paradigm for active IPv6 address discovery is first to leverage IPv6 hitlists, a collection of known active IPv6 addresses, as seed addresses to generate more candidate IPv6 addresses and then verify their activeness. However, prior work fails to achieve high performance with acceptable overhead, and is also weak in detecting aliased prefixes. 

In this paper, we propose 6Prob, a probabilistic generation model combined with tree-based data structure to discover active IPv6 addresses on the global Internet efficiently. By abstracting the address generation problem as a process of recursively selecting sub-prefixes based on probability, 6Prob can achieve both high performance and low overhead when generating candidate addresses. Besides, we design a cool-down aliased prefix detection (APD) scheme to alleviate the saturation scanning problem in detecting aliased prefixes. Further, we use the detected aliased prefixes to improve the quality of the seed addresses since aliased prefixes can mislead the probabilistic generation model. The experimental results show that compared to prior work, 6Prob can generate 81.4% more active addresses with significantly lower memory overhead.  Moreover, we perform measurements on SSH and TLS in IPv6 to prove 6Prob's ability to support IPv6 measurement and to reveal the latest image of IPv6 security.

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
> Module `filAlias` is used to filter addresses in the input file with aliased prefixes in the alias file and output results to the output file.

```
6prob -module=gen -input=<input file> -output=<output file> -alias=<alias file> -budget=<# generated addresses> -out-alias=<alias output file> [-source-ip=<source IP> -n-proc=<# processes for generating and updating> -n-scan-proc=<# scan processes>]
```
> Module `gen` uses 6Prob model to generate new addresses based on addresses in the input file. Alias file is used to prevent model generating alias addresses. Budget is the number of generated addresses you want. Alias output file is used to store the aliased prefixes detected by the online cool-down APD.

> 6Prob need input file (often active addresses in the IPv6 Hitlist) as heuristics. During the generation, it avoids generating aliased addresses by filtering generated addresses by aliased file and performing online cool-down APD. The newly-detected aliased prefixes from the online cool-down APD is exported to alias output file.

```
6prob -module=detAlias -input=<input file> -output=<output file> [-source-ip=<source IP> -n-scan-proc=<# scan processes>]
```
> Module `detAlias` uses cool-down detection for aliased prefixes to detect aliased prefixes in the input file and output them to the output file.

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
> Module `genAlias` generates new aliased prefixes based on ones in the input file with the threshold distance.














