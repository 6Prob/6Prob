package _6gen

type TreeNode struct {
	ChildNodes []*TreeNode
	Prefix     *Addr6
}

func (root *TreeNode) Contains(addr *Addr6) bool {
	nowNode := root
	for i := 0; i < len(addr.IP); i++ {
		nextVal := addr.IP[i].GetVal()[0]
		if nowNode.ChildNodes[nextVal] == nil {
			return false
		}
	}
	return true
}

func (root *TreeNode) AddAddr(addr *Addr6) {
	// If it is a range, expands it and add one by one.
	if addr.IsRange() {
		for _, expandedAddr := range addr.ExpandRange() {
			root.AddAddr(expandedAddr)
		}
		return
	}
	nowNode := root
	gran := addr.Gran
	for i := 0; i < len(addr.IP); i++ {
		nextVal := addr.IP[i].GetVal()[0]
		if nowNode.ChildNodes[nextVal] == nil {
			var prefix *Addr6
			if i == len(addr.IP) {
				prefix = addr
			} else {
				prefix = nowNode.Prefix.Copy()
				prefix.IP = append(prefix.IP, Wildcard{val: 1 << nextVal})
			}
			newNode := &TreeNode{
				ChildNodes: make([]*TreeNode, 1<<gran),
				Prefix:     prefix,
			}
			nowNode.ChildNodes[nextVal] = newNode
		}
		nowNode = nowNode.ChildNodes[nextVal]
	}
}

func InitTree(addrs []*Addr6) *TreeNode {
	if len(addrs) == 0 {
		panic("Seed array cannot be empty.")
	}
	gran := addrs[0].Gran
	root := &TreeNode{
		ChildNodes: make([]*TreeNode, 1<<gran),
		Prefix: &Addr6{
			IP:   make([]Wildcard, 0),
			Gran: gran,
		},
	}
	root.ChildNodes = make([]*TreeNode, 1<<gran)
	for _, addr := range addrs {
		root.AddAddr(addr)
	}
	return root
}

func (root *TreeNode) GetCoverage(addrRange *Addr6) []*Addr6 {
	gran := root.Prefix.Gran
	var nodeArray []*TreeNode
	var addrArray []*Addr6
	nodeArray = append(nodeArray, root)
	for len(nodeArray) != 0 {
		// get the first node from Array
		nowNode := nodeArray[0]
		nodeArray = nodeArray[1:]
		if len(nowNode.Prefix.IP) == AddrBitsLen/gran {
			addrArray = append(addrArray, nowNode.Prefix)
		} else {
			var rangeArray []uint8
			if addrRange == nil {
				for i := uint8(0); i < 1<<gran; i++ {
					rangeArray = append(rangeArray, i)
				}
			} else {
				rangeArray = addrRange.IP[len(nowNode.Prefix.IP)].GetVal()
			}
			for _, nextVal := range rangeArray {
				if nowNode.ChildNodes[nextVal] != nil {
					nodeArray = append(nodeArray, nowNode.ChildNodes[nextVal])
				}
			}
		}
	}
	return addrArray
}

func (root *TreeNode) GetCoveredSet(addrRange *Addr6) Uint128Set {
	addrArray := root.GetCoverage(addrRange)
	coveredSet := Uint128Set{}
	for _, addr := range addrArray {
		coveredSet[addr.ToInt128()] = true
	}
	return coveredSet
}
