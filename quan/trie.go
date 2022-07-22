package quan

import (
	"IPv6/utils"
	"fmt"
	"math"
	"net"
	"sync"
)

const (
	fk float64 = 3
	ak float32 = 1
	epsilon float32 = 0.01
)

func score(rpa, entropy float32) float32 {
	// This is function f
	math.Floor(1)
	return rpa / entropy
}

type QuanChildren struct {
	indices  utils.Indices
	children []*TrieNode
	mutex    *sync.RWMutex
}

type TrieNode struct {
	isPrefix    bool
	rpa         float32
	score       float32
	nActive     uint32
	nProbes     uint32
	children    QuanChildren
	path        utils.BitsArray
	mayBeAlias  bool
	forbidden   bool
	mutex       *sync.Mutex
}

type QuanTrie struct {
	rootNode   *TrieNode
	nilSlice   utils.BitsArray
	finishNode *TrieNode
	dealias     bool
}

func (cc *QuanChildren) IndexAt(i uint8) *TrieNode {
	// return children[i]
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()
	pos := cc.indices.Pos(i)
	if pos == -1 {
		return nil
	} else {
		return cc.children[pos]
	}
}

func (cc *QuanChildren) Set(i uint8, newChild *TrieNode) {
	// children[i] = newChild
	cc.mutex.Lock()
	defer cc.mutex.Unlock()
	pos := cc.indices.Pos(i)
	if pos == -1 {
		cc.indices.Add(i)
		pos = cc.indices.Pos(i)
		newChildren := make([]*TrieNode, len(cc.children) + 1)
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

func (cc *QuanChildren) Unset(i uint8) {
	// children[i] = finish
	cc.mutex.Lock()
	defer cc.mutex.Unlock()
	pos := cc.indices.Pos(i)
	cc.indices.Del(uint8(pos))
	newChildren := make([]*TrieNode, len(cc.children) - 1)
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

func (cc *QuanChildren) Clear() {
	// chilren.clear()
	cc.mutex.Lock()
	defer cc.mutex.Unlock()
	cc.indices = 0
	cc.children = nil
}

func (cc *QuanChildren) Range() []*TrieNode {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()
	children := make([]*TrieNode, 16)
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

func (cc *QuanChildren) ActiveRange(qTrie *QuanTrie) []*TrieNode {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()
	var children []*TrieNode
	for _, child := range cc.children {
		if child != qTrie.finishNode {
			children = append(children, child)
		}
	}
	return children
}

func (cc *QuanChildren) Replace(old, new *TrieNode) {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()
	for i, child := range cc.children {
		if child == old {
			cc.children[i] = new
			return
		}
	}
}

func (cc *QuanChildren) LenActive(qTrie *QuanTrie) uint8 {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()
	lenActive := uint8(0)
	for _, child := range cc.children {
		if child != qTrie.finishNode {
			lenActive ++
		}
	}
	return lenActive
}

func (cc *QuanChildren) LenNil() uint8 {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()
	return 16 - uint8(len(cc.children))
}

func (cc *QuanChildren) LenFinish(qTrie *QuanTrie) uint8 {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()
	lenFinish := uint8(0)
	for _, child := range cc.children {
		if child == qTrie.finishNode {
			lenFinish ++
		}
	}
	return lenFinish
}

func NewTrieNode(path utils.BitsArray) *TrieNode {
	return &TrieNode{
		isPrefix: false,
		// entropy:  0,
		score:    0,
		nActive:  0,
		nProbes:  0,
		children: QuanChildren{
			indices: 0, 
			children: make([]*TrieNode, 0),
			mutex: &sync.RWMutex{},
		},
		path:     path,
		mayBeAlias: true,
		forbidden: false,
		mutex:    &sync.Mutex{},
	}
}

func NewLeafTrieNode(path utils.BitsArray, qTrie *QuanTrie) *TrieNode {
	// Leaf node will use the last element of path as a leaf entry
	pathLen := path.Len() - 1
	leafNode := NewTrieNode(path.Slice(0, pathLen))
	leafVal := path.Back()
	leafNode.children.Set(leafVal, qTrie.finishNode)
	return leafNode
}

func (tNode *TrieNode) AliasCheck() bool {
	if tNode.nProbes >= 20 && tNode.nActive >= tNode.nProbes * 8 / 10 {
		return true
	} else {
		return false
	}
}

func (tNode *TrieNode) FinishCheck(qTrie *QuanTrie) bool {
	tNode.mutex.Lock()
	defer tNode.mutex.Unlock()
	for _, child := range tNode.children.Range() {
		if child != qTrie.finishNode {
			return false  // nothing happens
		}
	}
	pathLen := tNode.path.Len()
	if pathLen > 0 {
		val := tNode.path.Back()
		tNode.path = tNode.path.Slice(0, pathLen - 1)
		tNode.children.Clear()
		tNode.children.Set(val, qTrie.finishNode)
		return false
	} else {
		return true
	}
}

func (tNode *TrieNode) CalculateRpa(prevRpa float32, qTrie *QuanTrie) {
	/*
	 * Rpa is calculated from root to leaf.
	 * prevRpas is parent's Rpa
	 */
	if tNode == qTrie.rootNode {
		tNode.rpa = float32(tNode.nActive) / float32(tNode.nProbes)
	} else {
		tNode.rpa = (ak * prevRpa + float32(tNode.nActive)) / (float32(tNode.nProbes) + ak) + epsilon
		// tNode.rpa = 0.1 * prevRpa + 0.9 * float32(tNode.nActive) / float32(tNode.nProbes)
	}
}

func (tNode *TrieNode) CalculateScore(qTrie *QuanTrie) {
	/*
     * Calculate function f
	 */
	tNode.mutex.Lock()
	defer tNode.mutex.Unlock()
	newScore := float32(0)
	if tNode.children.LenActive(qTrie) > 0 {
		probs := tNode.CalculateProbs(qTrie)
		for i, prob := range probs {
			if tNode.children.IndexAt(uint8(i)) != nil {
				newScore += prob * tNode.children.IndexAt(uint8(i)).score
			}
		}
		tNode.score = newScore
	} else {
		tNode.score = tNode.rpa
	}
}

func (tNode *TrieNode) CalculateProbs(qTrie *QuanTrie) []float32 {
	prob := make([]float32, 16)
	totScore := float32(0)
	lenFinish := tNode.children.LenFinish(qTrie)
	maxScore := float32(0)
	maxRpa := float32(0)
	for _, child := range tNode.children.Range() {
		if child == qTrie.finishNode || child == nil || child.forbidden {
			continue
		}
		if maxScore < child.score {
			maxScore = child.score
		}
		if maxRpa < child.rpa {
			maxRpa = child.rpa
		}
	}
	for i, child := range tNode.children.Range() {
		if child == qTrie.finishNode {
			continue
		}
		if child == nil {
			if lenFinish > 0 {
				prob[i] = score(tNode.rpa, 16)
			}
		} else if !child.forbidden {
			// prob[i] = float32(math.Exp(fk * float64(child.score))) - 1
			// prob[i] = child.score
			// prob[i] = float32(math.Pow(float64(child.score), 2))
			// prob[i] = float32(0.5 * math.Sin(math.Pi * (float64(child.score / maxScore) - 0.5)) + 0.5)
			prob[i] = float32(1 / (1 + math.Exp(-fk * math.Tan(math.Pi * float64(child.score / maxScore - 0.5)))))
			// prob[i] = child.rpa
			// if child.score == maxScore {
			// prob[i] = 1
			// }
		}
		totScore += prob[i]
	}
	if totScore == 0 {
		for i, child := range tNode.children.Range() {
			if child == qTrie.finishNode {
				continue
			} else if child != nil && !child.forbidden {
				prob[i] = 1
			}
		}
		totScore += 1
	}
	for i := range prob {
		prob[i] /= totScore
	}
	return prob
}

func (tNode *TrieNode) Split(i uint8, newPath utils.BitsArray, qTrie *QuanTrie) (*TrieNode, *TrieNode) {
	/*
     * Split this node with newPath at i. This indicates tNode.path[:i] == newPath[:i].
	 * If i >= newPath.Len, there is no sibling. The node just split into two halves.
	 */
	valMe      := tNode.path.IndexAt(i)
	newFather  := NewTrieNode(newPath.Slice(0, i))
	var newSibling *TrieNode
	tNode.path  = tNode.path.Slice(i + 1)
	newFather.nActive = tNode.nActive
	newFather.nProbes = tNode.nProbes
	newFather.children.Set(valMe, tNode)
	if i < newPath.Len() {
		valSib := newPath.IndexAt(i)
		// fmt.Println(newPath.Len())
		newSibling = NewLeafTrieNode(newPath.Slice(i + 1), qTrie)
		newFather.children.Set(valSib, newSibling)
	}
	return newFather, newSibling
}

func (tNode *TrieNode) Walk(newPath utils.BitsArray, qTrie *QuanTrie, nodesOnPath []*TrieNode) (utils.BitsArray, []*TrieNode) {
	/*
	 * If this node matches the path, then return child, nil
	 * If this node has branch with the path, then expand this node and return father, child
	 * nodesOnPath records all nodes visited in this walk, this node is already in it.
	 *
	 * The returned value path, isSplitted, nodesOnPath
	 * path is what newPath remains when out this node
	 * isSplitted is whether this node is splitted
	 * nodesOnPath records all nodes visited in this walk, new appending will often lead to different pointer
	 */
	tNode.mutex.Lock()
	defer tNode.mutex.Unlock()
	// Search for branch
	i := uint8(0)
	hasBran := false
	for ; i < tNode.path.Len(); i ++ {
		if tNode.path.IndexAt(i) != newPath.IndexAt(i) {
			hasBran = true
			break
		}
	}
	if !hasBran {
		val := newPath.IndexAt(i)
		if i == newPath.Len() - 1 {  // If this is the last gran of the address
			if tNode.children.IndexAt(val) == nil {  // probe
				tNode.children.Set(val, qTrie.finishNode)
			}
			return qTrie.nilSlice, nodesOnPath
		} else {
			nextPath := newPath.Slice(i + 1)
			if tNode.children.IndexAt(val) == nil {  // new entry
				newLeaf := NewLeafTrieNode(nextPath, qTrie)
				tNode.children.Set(val, newLeaf)
				nodesOnPath = append(nodesOnPath, newLeaf)
				return qTrie.nilSlice, nodesOnPath
			} else {  // old entry
				nodesOnPath = append(nodesOnPath, tNode.children.IndexAt(val))
				return nextPath, nodesOnPath
			}
		}
	} else {  // split
		newFather, newSibling := tNode.Split(i, newPath, qTrie)
		prevNode := nodesOnPath[len(nodesOnPath) - 2]
		prevNode.children.Replace(tNode, newFather)
		nodesOnPath[len(nodesOnPath) - 1] = newFather
		nodesOnPath = append(nodesOnPath, newSibling)
		return qTrie.nilSlice, nodesOnPath
	}
}

func (tNode *TrieNode) RecCalculate(prevRpa float32, qTrie *QuanTrie) {
	tNode.CalculateRpa(prevRpa, qTrie)
	for _, child := range tNode.children.Range() {
		if child != nil && child != qTrie.finishNode {
			child.RecCalculate(tNode.rpa, qTrie)
		}
	}
	tNode.CalculateScore(qTrie)
}

func (tNode *TrieNode) Generate(newAddr utils.BitsArray, qTrie *QuanTrie, nodesOnPath []*TrieNode) (utils.BitsArray, []*TrieNode) {
	tNode.mutex.Lock()
	defer tNode.mutex.Unlock()
	// walk through path
	i := uint8(0)
	for ; i < tNode.path.Len(); i ++ {
		val := tNode.path.IndexAt(i)
		newAddr.Append(val)
	}
	// select next entry
	next := utils.RandBranchFloat(tNode.CalculateProbs(qTrie))
	newAddr.Append(next)
	orgLen := newAddr.Len()
	if tNode.children.IndexAt(next) == nil {  // new entry
		if orgLen == 32 {
			tNode.children.Set(next, qTrie.finishNode)
		} else {
			newAddr = newAddr.RandFill()
			newLeafNode := NewLeafTrieNode(newAddr.Slice(orgLen), qTrie)
			tNode.children.Set(next, newLeafNode)
		}
	}
	nodesOnPath = append(nodesOnPath, tNode.children.IndexAt(next))
	return newAddr, nodesOnPath
}

func NewQuanTrie(dealias bool) *QuanTrie {
	ba := utils.NewBitsArray(0, nil)
	return &QuanTrie{
		rootNode:   NewTrieNode(ba),
		finishNode: NewTrieNode(ba),
		nilSlice:   ba,
		dealias:    dealias,
	}
}

func (qTrie *QuanTrie) CalculatePath(nodesOnPath []*TrieNode) {
	/*
     * Recalculate Rpa and prob of nodes in nodesOnPath.
	 */
	// finish check
	pathLen := len(nodesOnPath)
	for i := len(nodesOnPath) - 1; i > -1; i -- {
		node := nodesOnPath[i]
		if node.FinishCheck(qTrie) {
			nodesOnPath[i - 1].children.Replace(node, qTrie.finishNode)
			pathLen --
		}
	}
	nodesOnPath = nodesOnPath[ : pathLen]
	// calculate Rpa from root to leaf
	prevRpa := float32(0)
	for _, node := range nodesOnPath {
		node.CalculateRpa(prevRpa, qTrie)
		prevRpa = node.rpa
	}
	// calculate entropy and score from leaf to root
	for i := len(nodesOnPath) - 1; i > -1; i -- {
		node := nodesOnPath[i]
		// node.CalculateEntropy(qTrie)
		node.CalculateScore(qTrie)
	}
}

func (qTrie *QuanTrie) InitCalculate() {
	qTrie.rootNode.RecCalculate(0, qTrie)
}

func (qTrie *QuanTrie) Add(addr net.IP, init bool, isProbe bool) {
	// add a probe IPv6 to the trie
	// isProbe == true: probe, isProbe == false: active
	addrBits := utils.NewBitsArray(32, []byte(addr))
	nowNode := qTrie.rootNode
	var nodesOnPath []*TrieNode
	nodesOnPath = append(nodesOnPath, nowNode)
	for !addrBits.Empty() {
		addrBits, nodesOnPath = nowNode.Walk(addrBits, qTrie, nodesOnPath)
		nowNode = nodesOnPath[len(nodesOnPath) - 1]
		if nowNode == qTrie.finishNode {
			nodesOnPath = nodesOnPath[ : len(nodesOnPath) - 1]
			break
		}
	}
	for _, node := range nodesOnPath {
		if isProbe{
			node.nProbes ++
		} else {
			node.nActive ++
		}
	}
	if !init {
		qTrie.CalculatePath(nodesOnPath)
	} else {
		for _, node := range nodesOnPath {
			node.mayBeAlias = false
		}
	}
}

func (qTrie *QuanTrie) AddAlias(aliasStr string, isAlias bool) uint32 {
	_, alias, _ := net.ParseCIDR(aliasStr)
	aliasBits := utils.Pfx2Bits(alias)[0]
	var nowFather *TrieNode
	nowNode := qTrie.rootNode
	nodesOnPath := make([]*TrieNode, 1)
	nodesOnPath[0] = qTrie.rootNode
	val := uint8(0)
	for i := uint8(0); i < aliasBits.Len(); i ++ {
		val = aliasBits.IndexAt(i)
		nowFather = nowNode
		nowNode = nowNode.children.IndexAt(val)
		if nowNode == nil {
			return 0
		}
		nodesOnPath = append(nodesOnPath, nowNode)
		i += nowNode.path.Len()
	}
	nActive := nowNode.nActive
	if isAlias {
		qTrie.CalculatePath(nodesOnPath)
		if nowNode.path.Len() == 0 {
			nowFather.children.Set(val, qTrie.finishNode)
		} else {
			lastVal := nowNode.path.Back()
			nowNode.path = nowNode.path.Slice(4, 0, nowNode.path.Len() - 1)
			nowNode.children.Clear()
			nowNode.children.Set(lastVal, qTrie.finishNode)
			nowNode.forbidden = false
		}
	} else {
		nowNode.forbidden = false
		nowNode.mayBeAlias = false
	}
	return nActive
}

func (qTrie *QuanTrie) PrintProbs() {
	if qTrie.rootNode.children.IndexAt(2) == nil {
		return
	}
	fmt.Println(qTrie.rootNode.nProbes, qTrie.rootNode.nActive, qTrie.rootNode.score)
	checkNode := qTrie.rootNode.children.IndexAt(2)
	checkNode = checkNode.children.IndexAt(10)
	checkNode = checkNode.children.IndexAt(0)
	probs := checkNode.CalculateProbs(qTrie)
	for i, child := range checkNode.children.Range() {
		if child != nil {
			fmt.Println(i, child.score, probs[i], child.nProbes, child.nActive)
		} else {
			fmt.Println(i, 0, probs[i])
		}
	}
}

func (qTrie *QuanTrie) Generate() (bool, string) {
	// Generate a probe IPv6 from the tree
	newAddr := utils.NewBitsArray(0, nil)
	nowNode := qTrie.rootNode
	var nodesOnPath []*TrieNode
	nodesOnPath = append(nodesOnPath, nowNode)
	for newAddr.Len() < 32 {
		newAddr, nodesOnPath = nowNode.Generate(newAddr, qTrie, nodesOnPath)
		nowNode = nodesOnPath[len(nodesOnPath) - 1]
		if qTrie.dealias && nowNode.mayBeAlias && nowNode.AliasCheck() {
			nowNode.forbidden = true
			return true, newAddr.ToPrefix6()
		}
	}
	for _, node := range nodesOnPath {
		node.nProbes ++
	}
	qTrie.CalculatePath(nodesOnPath)
	return false, newAddr.ToIPv6()
}

func (qTrie *QuanTrie) Has(addr net.IP) bool {
	// check whether the give address is in the trie
	i := uint8(0)
	addrBits := utils.NewBitsArray(32, []byte(addr))
	nowNode := qTrie.rootNode
	for {
		for j := uint8(0); j < nowNode.path.Len(); j ++ {
			if nowNode.path.IndexAt(j) != addrBits.IndexAt(i) {
				return false
			} else {
				i ++
			}
		}
		nextVal := addrBits.IndexAt(i)
		i ++
		if nowNode.children.IndexAt(nextVal) == nil {
			return false
		} else if nowNode.children.IndexAt(nextVal) == qTrie.finishNode {
			return true
		} else {
			nowNode = nowNode.children.IndexAt(nextVal)
		}
	}
}

func (qTrie *QuanTrie) GetValuablePfx(thres uint32) []string {
	// Get prefixes with more than thres targets
	var nodeArray []*TrieNode
	var bitsArray []utils.BitsArray
	var pfxStrArray []string
	nodeArray = append(nodeArray, qTrie.rootNode)
	bitsArray = append(bitsArray, utils.NilSlice())
	for len(nodeArray) != 0 {
		nowNode := nodeArray[0]
		nowBits := bitsArray[0]
		nodeArray = nodeArray[1:]
		bitsArray = bitsArray[1:]
		if nowNode.nProbes < thres {
			continue
		}
		if nowBits.Len() >= 16 {
			pfxStrArray = append(pfxStrArray, nowBits.ToPrefix6())
		}
		for i := uint8(0); i < nowNode.path.Len(); i ++ {
			nowBits.Append(nowNode.path.IndexAt(i))
			if nowBits.Len() >= 16 && nowBits.Len() < 29 {
				pfxStrArray = append(pfxStrArray, nowBits.ToPrefix6())
			}
		}
		if nowBits.Len() < 28  { // only prefix length with or less than 112
			for i, child := range nowNode.children.Range() {
				if child != nil && child != qTrie.finishNode {
					nodeArray = append(nodeArray, child)
					nextBits := nowBits.Copy()
					nextBits.Append(byte(i))
					bitsArray = append(bitsArray, nextBits)
				}
			}
		}
	}
	return pfxStrArray
}

func (qTrie *QuanTrie) GetEstimation() float32 {
	return qTrie.rootNode.score * 100
}
