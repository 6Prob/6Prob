package quan

import (
	"IPv6/utils"
	"net"
	"time"
	"math"
	"fmt"
)

const (
	cooldown int64 = 2000
	maxRetries uint8 = 1
)

type AliasTestNode struct {
	children []*AliasTestNode
}

type AliasTestTree struct {
	rootNode   *AliasTestNode
	finishNode *AliasTestNode
}

func NewAliasTestNode() *AliasTestNode {
	children := make([]*AliasTestNode, 16)
	return &AliasTestNode{children: children}
}

func NewAliasTestTree() *AliasTestTree {
	return &AliasTestTree{
		rootNode: NewAliasTestNode(),
		finishNode: NewAliasTestNode(),
	}
}

func (at *AliasTestTree) AddAlias(alias *net.IPNet) {
	nowNode := at.rootNode
	aliasBits := utils.Pfx2Bits(alias)[0]
	for i := uint8(0); i < aliasBits.Len() - 1; i ++ {
		val := aliasBits.IndexAt(i)
		if nowNode.children[val] == nil {
			nowNode.children[val] = NewAliasTestNode()
		}
		nowNode = nowNode.children[val]
	}
	nowNode.children[aliasBits.Back()] = at.finishNode
}

func (at *AliasTestTree) IsAlias(addr net.IP) bool {
	nowNode := at.rootNode
	addrBits := utils.NewBitsArray(32, []byte(addr))
	for i := uint8(0); i < 32; i ++ {
		val := addrBits.IndexAt(i)
		if nowNode.children[val] == nil {
			return false
		} else if nowNode.children[val] == at.finishNode {
			return true
		} else {
			nowNode = nowNode.children[val]
		}
	}
	return false
}

func (at *AliasTestTree) IsAliasPfx(pfx *net.IPNet) bool {
	nowNode := at.rootNode
	pfxBits := utils.Pfx2Bits(pfx)[0]
	for i := uint8(0); i < pfxBits.Len(); i ++ {
		val := pfxBits.IndexAt(i)
		if nowNode.children[val] == nil {
			return false
		} else if nowNode.children[val] == at.finishNode {
			return true
		} else {
			nowNode = nowNode.children[val]
		}
	}
	return false
}

type AliasCompChildren struct {
	indices utils.Indices
	children []*AliasNode
}

func (cc *AliasCompChildren) IndexAt(i uint8) *AliasNode {
	// return children[i]
	pos := cc.indices.Pos(i)
	if pos == -1 {
		return nil
	} else {
		return cc.children[pos]
	}
}

func (cc *AliasCompChildren) Set(i uint8, newChild *AliasNode) {
	// children[i] = newChild
	pos := cc.indices.Pos(i)
	if pos == -1 {
		cc.indices.Add(i)
		pos = cc.indices.Pos(i)
		newChildren := make([]*AliasNode, len(cc.children) + 1)
		j := int8(0)
		for ; j < pos; j ++ {
			newChildren[j] = cc.children[j]
		}
		newChildren[j] = newChild
		j ++
		for ; j < int8(len(newChildren)); j ++ {
			newChildren[j] = cc.children[j - 1]
		}
		cc.children = newChildren
	} else {
		cc.children[pos] = newChild
	}
}

func (cc *AliasCompChildren) Unset(i uint8) {
	// children[i] = finish
	pos := cc.indices.Pos(i)
	cc.indices.Del(uint8(pos))
	newChildren := make([]*AliasNode, len(cc.children) - 1)
	j := int8(0)
	for ; j < pos; j ++ {
		newChildren[j] = cc.children[j]
	}
	j ++
	for ; j < int8(len(newChildren)); j ++ {
		newChildren[j - 1] = cc.children[j]
	}
	cc.children = newChildren
}

func (cc *AliasCompChildren) Clear() {
	// chilren.clear()
	cc.indices = 0
	cc.children = nil
}

func (cc *AliasCompChildren) Range() []*AliasNode {
	children := make([]*AliasNode, 16)
	for i := uint8(0); i < 16; i ++ {
		pos := cc.indices.Pos(i)
		if pos == -1 {
			children[i] = nil
		} else {
			children[i] = cc.children[pos]
		}
	}
	return children
}

func (cc *AliasCompChildren) RangeValid() []*AliasNode {
	return cc.children
}

func (cc *AliasCompChildren) Replace(old, new *AliasNode) {
	for i, child := range cc.children {
		if child == old {
			cc.children[i] = new
			return
		}
	}
}

func (cc *AliasCompChildren) Len() uint8 {
	return uint8(len(cc.children))
}

type AliasNode struct {
	isActive   bool
	mayBeAlias bool
	path       utils.BitsArray
	children   AliasCompChildren
	lastVisit  int64
	probe      utils.Indices
	active     utils.Indices
	retries    uint8
}

type AliasTrie struct {
	rootNode *AliasNode
}

func NewAliasNode(path utils.BitsArray) *AliasNode {
	return &AliasNode{
		isActive: true,
		mayBeAlias: true,
		path: path,
		children: AliasCompChildren{
			indices: 0,
			children: make([]*AliasNode, 0),
		},
		lastVisit: 0,
		probe: 0,
		active: 0,
		retries: 0,
	}
}

func NewAliasLeafNode(path utils.BitsArray) *AliasNode {
	return NewAliasNode(path.Slice(4, 0, path.Len() - 2))
}

func (aNode *AliasNode) GetNextAddr(newAddr utils.BitsArray) utils.BitsArray {
	nowVal := aNode.probe.GetMax()
	if aNode.probe == aNode.active {
		nowVal ++
		aNode.retries = 1
		aNode.probe.Add(nowVal)
	} else {
		aNode.retries ++
	}
	newAddr.Append(nowVal)
	newAddr.RandFill()
	return newAddr
}

func (aNode *AliasNode) CheckActive(pfxLen uint8) bool {
	// If timing is right and the node is a leaf, check the necessity of continuing probing
	nonAlias := false
	for _, child := range aNode.children.RangeValid() {
		// If there are active children, the node is active
		if child.isActive {
			return true
		} else if !child.IsAlias() {
			nonAlias = true
		}
	}
	if !aNode.mayBeAlias || nonAlias || aNode.CannotBeAlias() {
		// If has non-alias children, the node is inactive
		// If this node is not alias, the node is inactive
		aNode.isActive = false
	} else if aNode.active == 0xffff {  // the node is alias (detection is done)
		if aNode.path.Len() > 0 {
			lastVal := aNode.path.Back()
			aNode.path = aNode.path.Slice(4, 0, aNode.path.Len() - 1)
			aNode.children = AliasCompChildren{0, nil}
			aNode.probe = 0
			aNode.probe.Add(lastVal)
			aNode.active = 0
			aNode.active.Add(lastVal)
			aNode.retries = 0
			newChild := NewAliasNode(utils.NilSlice())
			newChild.isActive = false
			newChild.active = 0xffff
			aNode.children.Set(lastVal, newChild)
		} else {
			aNode.isActive = false
		}
	} else if pfxLen < 16 {
		aNode.isActive = false
	}
	return aNode.isActive
}

func CheckPath(nodesOnPath []*AliasNode) {
	// When last node is finished, check all its predecessors
	pfxLen := uint8(0)
	for _, node := range nodesOnPath {
		pfxLen += node.path.Len()
	}
	pfxLen += uint8(len(nodesOnPath) - 1)
	for i := len(nodesOnPath) - 1; i > -1; i -- {
		node := nodesOnPath[i]
		if node.CheckActive(pfxLen) {
			break
		}
		pfxLen -= node.path.Len() + 1
	}
}

func (aNode *AliasNode) CannotBeAlias() bool {
	return aNode.probe != aNode.active && aNode.retries == maxRetries
}

func (aNode *AliasNode) IsAlias() bool {
	return aNode.active == 0xffff
}

func (aNode *AliasNode) IsLeaf() bool {
	// node with no active children and no unaliased children is leaf
	for _, child := range aNode.children.RangeValid() {
		if child.isActive {
			return false
		}
	}
	return true
}

func (aNode *AliasNode) Split(i uint8, newPath utils.BitsArray) (*AliasNode, *AliasNode) {
	valMe := aNode.path.IndexAt(i)
	newFather := NewAliasNode(newPath.Slice(4, 0, i))
	var newSibling *AliasNode
	aNode.path = aNode.path.Slice(4, i + 1)
	newFather.children.Set(valMe, aNode)
	if i < newPath.Len() {
		valSib := newPath.IndexAt(i)
		newSibling = NewAliasLeafNode(newPath.Slice(4, i + 1))
		newFather.children.Set(valSib, newSibling)
	}
	return newFather, newSibling
}

func (aNode *AliasNode) Walk(newPath utils.BitsArray, nodesOnPath []*AliasNode, init bool) (utils.BitsArray, []*AliasNode) {
	i := uint8(0)
	hasBran := false
	for ; i < aNode.path.Len(); i ++ {
		if aNode.path.IndexAt(i) != newPath.IndexAt(i) {
			hasBran = true
			break
		}
	}
	if !hasBran {
		pfxLen := uint8(0)
		for _, node := range nodesOnPath {
			pfxLen += node.path.Len()
		}
		val := newPath.IndexAt(i)
		if i == newPath.Len() - 2 {  // If this is the last gran of the address
			if !init {
				aNode.active.Add(val)
				nowTime := time.Now().UnixMilli()
				if nowTime - aNode.lastVisit > cooldown {
					if !aNode.CheckActive(pfxLen) {
						CheckPath(nodesOnPath)
					}
				}
			}
			return utils.NilSlice(), nodesOnPath
		} else {
			nextPath := newPath.Slice(4, i + 1)
			nextChild := aNode.children.IndexAt(val)
			if nextChild == nil || !nextChild.isActive {  // new entry
				if init {
					newLeaf := NewAliasLeafNode(nextPath)
					aNode.children.Set(val, newLeaf)
					nodesOnPath = append(nodesOnPath, newLeaf)
					return utils.NilSlice(), nodesOnPath
				} else {
					aNode.active.Add(val)
					nowTime := time.Now().UnixMilli()
					if nowTime - aNode.lastVisit > cooldown {
						if !aNode.CheckActive(pfxLen) {
							CheckPath(nodesOnPath)
						}
					}
					return utils.NilSlice(), nodesOnPath
				}
			} else {  // old entry
				nodesOnPath = append(nodesOnPath, aNode.children.IndexAt(val))
				return nextPath, nodesOnPath
			}
		}
	} else {  // split
		newFather, newSibling := aNode.Split(i, newPath)
		prevNode := nodesOnPath[len(nodesOnPath) - 2]
		prevNode.children.Replace(aNode, newFather)
		nodesOnPath[len(nodesOnPath) - 1] = newFather
		nodesOnPath = append(nodesOnPath, newSibling)
		return utils.NilSlice(), nodesOnPath
	}
}

func (aNode *AliasNode) Generate(newAddr utils.BitsArray, nodesOnPath []*AliasNode) (utils.BitsArray, []*AliasNode, string) {
	if aNode.mayBeAlias {
		for _, child := range aNode.children.RangeValid() {
			if !child.isActive && !child.IsAlias() {
				aNode.mayBeAlias = false
				break
			}
		}
	}
	if aNode.mayBeAlias && newAddr.Len() + aNode.path.Len() > 16 {  // check timing
		if time.Now().UnixMilli() - aNode.lastVisit < cooldown {  // start over
			return utils.NilSlice(), nodesOnPath[:1], ""
		}
	}
	i := uint8(0)
	for ; i < aNode.path.Len(); i ++ {
		val := aNode.path.IndexAt(i)
		newAddr.Append(val)
	}
	if aNode.IsLeaf() {  // select probe address randomly
		if !aNode.CheckActive(newAddr.Len()) {
			CheckPath(nodesOnPath)
			return utils.NilSlice(), nodesOnPath[:1], ""
		} else {
			pfxStr := newAddr.ToPrefix6()
			newAddr = aNode.GetNextAddr(newAddr)
			return newAddr, nodesOnPath, pfxStr
		}
	} else {  // select next entry randomly
		var cand []*AliasNode
		var candBranch []uint8
		for j, child := range aNode.children.Range() {
			if child != nil && child.isActive {
				cand = append(cand, child)
				candBranch = append(candBranch, uint8(j))
			}
		}
		nextVal := candBranch[utils.RandEven(len(cand))]
		newAddr.Append(nextVal)
		nodesOnPath = append(nodesOnPath, aNode.children.IndexAt(nextVal))
		return newAddr, nodesOnPath, ""
	}
}

func (aNode *AliasNode) RecGetAliasPfx(pfxBits utils.BitsArray, init bool) []string {
	var pfxArray []string
	for i := uint8(0); i < aNode.path.Len(); i ++ {
		pfxBits.Append(aNode.path.IndexAt(i))
	}
	if (init && aNode.mayBeAlias) || aNode.IsAlias() {
		pfxArray = append(pfxArray, pfxBits.ToPrefix6())
	} else {
		for i, child := range aNode.children.Range() {
			if child != nil {
				childPfxBits := pfxBits.Copy()
				childPfxBits.Append(uint8(i))
				pfxArray = append(pfxArray, child.RecGetAliasPfx(childPfxBits, init)...)
			}
		}
	}
	return pfxArray
}

func (aNode *AliasNode) RecGetAliasPfxTD(pfxBits utils.BitsArray) []string {
	var pfxArray []string
	for i := uint8(0); i < aNode.path.Len(); i ++ {
		pfxBits.Append(aNode.path.IndexAt(i))
	}
	if aNode.mayBeAlias && pfxBits.Len() >= 16 {
		pfxArray = append(pfxArray, pfxBits.ToPrefix6())
	} else {
		for i, child := range aNode.children.Range() {
			if child != nil {
				childPfxBits := pfxBits.Copy()
				childPfxBits.Append(uint8(i))
				pfxArray = append(pfxArray, child.RecGetAliasPfxTD(childPfxBits)...)
			}
		}
	}
	return pfxArray
}

func NewAliasTrie() *AliasTrie {
	fmt.Print()
	aTrie := &AliasTrie{
		rootNode: NewAliasNode(utils.NilSlice()),
	}
	aTrie.rootNode.mayBeAlias = false
	return aTrie
}

func (aTrie *AliasTrie) Add(addr net.IP) {
	addrBits := utils.NewBitsArray(32, []byte(addr))
	nowNode := aTrie.rootNode
	var nodesOnPath []*AliasNode
	nodesOnPath = append(nodesOnPath, nowNode)
	for !addrBits.Empty() {
		addrBits, nodesOnPath = nowNode.Walk(addrBits, nodesOnPath, false)
		nowNode = nodesOnPath[len(nodesOnPath) - 1]
	}
	for _, node := range nodesOnPath {
		node.lastVisit = 0
	}
}

func (aTrie *AliasTrie) AddPfx(pfx *net.IPNet, recur bool) {
	if pfx == nil {
		return
	}
	pfxBits := utils.Pfx2Bits(pfx)[0]
	nowNode := aTrie.rootNode
	for i, val := range pfxBits.Range() {
		if nowNode.children.IndexAt(val) == nil {
			newChild := NewAliasNode(utils.NilSlice())
			nowNode.children.Set(val, newChild)
			if !recur && uint8(i) != pfxBits.Len() - 1 {
				newChild.mayBeAlias = false
			}
		}
		nowNode = nowNode.children.IndexAt(val)
	}
	if !recur {
		nodeArray := make([]*AliasNode, 1)
		nodeArray[0] = nowNode
		for len(nodeArray) != 0 {
			nowNode = nodeArray[0]
			nodeArray = nodeArray[1:]
			nowNode.mayBeAlias = true
			nodeArray = append(nodeArray, nowNode.children.RangeValid()...)
		}
	}
}

func (aTrie *AliasTrie) AddPfxOnce(pfx *net.IPNet) {
	if pfx == nil {
		return
	}
	pfxBits := utils.Pfx2Bits(pfx)[0]
	nowNode := aTrie.rootNode
	for i, val := range pfxBits.Range() {
		if nowNode.children.IndexAt(val) == nil {
			newChild := NewAliasNode(utils.NilSlice())
			nowNode.children.Set(val, newChild)
			if uint8(i) != pfxBits.Len() - 1 {
				newChild.mayBeAlias = false
			}
		}
		nowNode = nowNode.children.IndexAt(val)
		if nowNode.mayBeAlias {
			break
		}
	}
}

func (aTrie *AliasTrie) Generate() (string, string) {
	// Generate a probe IPv6 from the trie
	newAddr := utils.NilSlice()
	nowNode := aTrie.rootNode
	if !nowNode.isActive {
		return "", ""
	}
	var nodesOnPath []*AliasNode
	nodesOnPath = append(nodesOnPath, nowNode)
	pfxStr := ""
	for newAddr.Len() < 32 {
		if !aTrie.rootNode.isActive {
			return "", ""
		}
		newAddr, nodesOnPath, pfxStr = nowNode.Generate(newAddr, nodesOnPath)
		nowNode = nodesOnPath[len(nodesOnPath) - 1]
	}
	nowTime := time.Now().UnixMilli()
	for _, node := range nodesOnPath {
		node.lastVisit = nowTime
	}
	return newAddr.ToIPv6(), pfxStr
}

func (aTrie *AliasTrie) GenerateTopDown() (string, string) {
	// Generate a probe IPv6 from the trie in the top down manner
	newAddr := utils.NilSlice()
	nowNode := aTrie.rootNode
	if !nowNode.isActive {
		return "", ""
	}
	pfxStr := ""
	for newAddr.Len() < 32 {
		if !aTrie.rootNode.isActive {
			return "", ""
		}
		if nowNode.mayBeAlias && newAddr.Len() >= 16 {
			if time.Now().UnixMilli() - nowNode.lastVisit < cooldown {  // restart over
				nowNode = aTrie.rootNode
				newAddr = utils.NilSlice()
			} else {
				if nowNode.CannotBeAlias() {
					nowNode.mayBeAlias = false
					nowNode = aTrie.rootNode
					newAddr = utils.NilSlice()
				} else if nowNode.IsAlias() {
					nowNode.isActive = false
					nowNode = aTrie.rootNode
					newAddr = utils.NilSlice()
				} else {
					pfxStr = newAddr.ToPrefix6()
					newAddr = nowNode.GetNextAddr(newAddr)
					nowNode.lastVisit = time.Now().UnixMilli()
				}
			}
		} else {
			var cand []*AliasNode
			var candBranch []uint8
			for j, child := range nowNode.children.Range() {
				if child != nil && child.isActive {
					cand = append(cand, child)
					candBranch = append(candBranch, uint8(j))
				}
			}
			if len(cand) == 0 {
				nowNode.isActive = false
				newAddr = utils.NilSlice()
				nowNode = aTrie.rootNode
			} else {
				nextVal := candBranch[utils.RandEven(len(cand))]
				newAddr.Append(nextVal)
				nowNode = nowNode.children.IndexAt(nextVal)
			}
		}
	}
	return newAddr.ToIPv6(), pfxStr
}

func (aTrie *AliasTrie) AddActiveTopDown(addr net.IP) {
	addrBits := utils.NewBitsArray(32, []byte(addr))
	nowNode := aTrie.rootNode
	for i, val := range addrBits.Range() {
		nowNode = nowNode.children.IndexAt(val)
		if nowNode == nil {
			break
		}
		if nowNode.mayBeAlias {
			nowNode.active.Add(addrBits.IndexAt(uint8(i + 1)))
			nowNode.lastVisit = 0
			nowNode.retries = 0
			break
		}
	}
}

func (aTrie *AliasTrie) GetAliasPfx(init bool) []string {
	return aTrie.rootNode.RecGetAliasPfx(utils.NilSlice(), init)
}

func (aTrie *AliasTrie) GetAliasPfxTD() []string {
	return aTrie.rootNode.RecGetAliasPfxTD(utils.NilSlice())
}

func (aTrie *AliasTrie) CountLeaf() (int, int) {
	leafCounter := 0
	pfxCounter := 0
	nodeArray := make([]*AliasNode, 1)
	nodeArray[0] = aTrie.rootNode
	for len(nodeArray) != 0 {
		nowNode := nodeArray[0]
		nodeArray = nodeArray[1:]
		if nowNode.mayBeAlias {
			pfxCounter ++
		}
		if len(nowNode.children.RangeValid()) == 0 {
			leafCounter ++
		} else {
			nodeArray = append(nodeArray, nowNode.children.RangeValid()...)
		}
	}
	return leafCounter, pfxCounter
}

func (aTrie *AliasTrie) CountNAddr(init bool) float64 {
	nAddr := float64(0)
	nodeArray := make([]*AliasNode, 1)
	pfxLenArray := make([]int, 1)
	nodeArray[0] = aTrie.rootNode
	pfxLenArray[0] = 0
	for len(nodeArray) != 0 {
		nowNode := nodeArray[0]
		nodeArray = nodeArray[1:]
		nowLen := pfxLenArray[0]
		pfxLenArray = pfxLenArray[1:]
		if (init && nowNode.mayBeAlias) || nowNode.IsAlias() {
			nAddr += math.Pow(2, float64(128 - 4 * nowLen))
		} else {
			for _, child := range nowNode.children.RangeValid() {
				nodeArray = append(nodeArray, child)
				pfxLenArray = append(pfxLenArray, nowLen + 1)
			}
		}
	}
	return nAddr
}

func (aTrie *AliasTrie) Has(pfx *net.IPNet) bool {
	if pfx == nil {
		return false
	}
	pfxBits := utils.Pfx2Bits(pfx)[0]
	nowNode := aTrie.rootNode
	for i := uint8(0); i < pfxBits.Len(); i ++ {
		for j := uint8(0); j < nowNode.path.Len(); j ++ {
			if nowNode.path.IndexAt(j) != pfxBits.IndexAt(i) {
				return false
			}
			i ++
			if i == pfxBits.Len() {
				return false
			}
		}
		val := pfxBits.IndexAt(i)
		nowNode = nowNode.children.IndexAt(val)
		if nowNode == nil {
			return false
		} else if nowNode.mayBeAlias {
			return true
		}
	}
	return false
}