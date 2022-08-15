package quan

import (
	"IPv6/utils"
	"sync"
	"math"
	"net"
	"fmt"
)

const (
	MaxEntropy16 float64 = 2.772588722239781  // log16
)

func f(x float32) float32 {
	if x < 0.25 {
		return 0.2 * x
	} else if x < 0.75 {
		return 1.8 * x - 0.4
	} else {
		return 0.2 * x + 0.8
	}
}

func AddrsEntropy(addrs []utils.BitsArray, remain utils.Indices32) []float64 {
	/*
	 * Calculate entropy at remain dimensions among addrs.
	 */
	remainArray := remain.GetAll()
	entropy := make([]float64, len(remainArray))
	for i, nowPos := range remainArray {
		counter := make([]int, 16)
		probs := make([]float64, 16)
		tot := 0
		for _, addrBits := range addrs {
			counter[addrBits.IndexAt(nowPos)] ++
		}
		for j := 0; j < 16; j ++ {
			tot += counter[j]
		}
		for j := range probs {
			if counter[j] == 0 {
				continue
			}
			if counter[j] == tot {
				entropy[i] = 0
				break
			}
			prob := float64(counter[j]) / float64(tot)
			entropy[i] -= prob * math.Log(prob)
		}
	}
	return entropy
}

type ProbChildren struct {
	indices  utils.Indices
	children []*ProbNode
	mutex    *sync.RWMutex
}

func (cc *ProbChildren) IndexAt(i uint8) *ProbNode {
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

func (cc *ProbChildren) Set(i uint8, newChild *ProbNode) {
	// children[i] = newChild
	cc.mutex.Lock()
	defer cc.mutex.Unlock()
	pos := cc.indices.Pos(i)
	if pos == -1 {
		cc.indices.Add(i)
		pos = cc.indices.Pos(i)
		newChildren := make([]*ProbNode, len(cc.children) + 1)
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

func (cc *ProbChildren) Unset(i uint8) {
	// children[i] = finish
	cc.mutex.Lock()
	defer cc.mutex.Unlock()
	pos := cc.indices.Pos(i)
	cc.indices.Del(uint8(pos))
	newChildren := make([]*ProbNode, len(cc.children) - 1)
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

func (cc *ProbChildren) Clear() {
	// chilren.clear()
	cc.mutex.Lock()
	defer cc.mutex.Unlock()
	cc.indices = 0
	cc.children = nil
}

func (cc *ProbChildren) Range() []*ProbNode {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()
	children := make([]*ProbNode, 16)
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

func (cc *ProbChildren) ActiveRange(pTree *ProbTree) []*ProbNode {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()
	var children []*ProbNode
	for _, child := range cc.children {
		if child != pTree.finishNode {
			children = append(children, child)
		}
	}
	return children
}

func (cc *ProbChildren) Replace(old, new *ProbNode) {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()
	for i, child := range cc.children {
		if child == old {
			cc.children[i] = new
			return
		}
	}
}

func (cc *ProbChildren) LenActive(pTree *ProbTree) uint8 {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()
	lenActive := uint8(0)
	for _, child := range cc.children {
		if child != pTree.finishNode {
			lenActive ++
		}
	}
	return lenActive
}

func (cc *ProbChildren) LenNil() uint8 {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()
	return 16 - uint8(len(cc.children))
}

func (cc *ProbChildren) LenFinish(pTree *ProbTree) uint8 {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()
	lenFinish := uint8(0)
	for _, child := range cc.children {
		if child == pTree.finishNode {
			lenFinish ++
		}
	}
	return lenFinish
}

type ProbNode struct {
	a float32
	q float32
	nActive uint32
	nProbes uint32
	divide  uint8
	children ProbChildren
	path utils.BitsArray
	indices utils.Indices32
	mutex *sync.Mutex
}

type ProbTree struct {
	rootNode *ProbNode
	finishNode *ProbNode
}

func NewProbNode(path utils.BitsArray, indices utils.Indices32, divide uint8) *ProbNode {
	return &ProbNode{
		a: 0,
		q: 0,
		nActive: 0,
		nProbes: 0,
		divide: divide,
		children: ProbChildren{
			indices: 0,
			children: make([]*ProbNode, 0),
			mutex: &sync.RWMutex{},
		},
		path: path,
		indices: indices,
		mutex: &sync.Mutex{},
	}
}

func NewLeafProbNode(path utils.BitsArray, indices utils.Indices32, pTree *ProbTree) *ProbNode {
	divide := indices.Pop()
	leafNode := NewProbNode(path.Slice(0, path.Len() - 1), indices, divide)
	leafVal := path.Back()
	leafNode.children.Set(leafVal, pTree.finishNode)
	return leafNode
}

func NewProbTree() *ProbTree {
	return &ProbTree{
		rootNode: NewProbNode(utils.NilSlice(), 0, 0),
		finishNode: NewProbNode(utils.NilSlice(), 0, 0),
	}
}

func (pNode *ProbNode) aCalculate(aprev float32, pTree *ProbTree) {
	/*
     * Active ratio a is calculated from root to leaf.
	 * aprev is parent's active ratio
	 */
	if pNode == pTree.rootNode {
		pNode.a = float32(pNode.nActive) / float32(pNode.nProbes)
	} else {
		pNode.a = (ak * aprev + float32(pNode.nActive)) / (float32(pNode.nProbes) + ak)
	}
}

func (pNode *ProbNode) qCalculate(pTree *ProbTree) {
	/*
     * Active probability of next probe q is calculated from leaf to root.
	 */
	pNode.mutex.Lock()
	defer pNode.mutex.Unlock()
	newQ := float32(0)
	if pNode.children.LenActive(pTree) > 0 {  // it is an intermediate node
		probs := pNode.pCalculate(pTree)
		if math.IsNaN(float64(probs[0])) {  // in case other goroutine finishes a child
			pNode.q = pNode.a
		} else {
			for i, prob := range probs {
				if pNode.children.IndexAt(uint8(i)) != nil {
					newQ += prob * pNode.children.IndexAt((uint8(i))).q
				}
			}
		}
		pNode.q = newQ
	} else {  // it is a leaf node
		pNode.q = pNode.a
	}
}

func (pNode *ProbNode) pCalculate(pTree *ProbTree) []float32 {
	prob := make([]float32, 16)
	totP := float32(0)
	lenActive := pNode.children.LenActive(pTree)
	maxQ := float32(0)
	for _, child := range pNode.children.ActiveRange(pTree) {
		if maxQ < child.q {
			maxQ = child.q
		}
	}
	maxQ += epsilon
	for i, child := range pNode.children.Range() {
		if child == pTree.finishNode {
			continue
		}
		if child == nil {
			if lenActive == 0 {  // there are no active branches, every branch has the same probability
				prob[i] = 1
			}
		} else {
			prob[i] = float32(1 / (1 + math.Exp(-fk * math.Tan(math.Pi * float64(child.q / maxQ - 0.5)))))
			// prob[i] = child.q
			// prob[i] = float32(math.Exp(10 * float64(child.q))) - 1
		}
		totP += prob[i]
	}
	if totP == 0 {
		for i, child := range pNode.children.Range() {
			if child == pTree.finishNode {
				continue
			} else if child != nil {
				prob[i] = 1
				totP += 1
			}
		}
	}
	for i := range prob {
		prob[i] /= totP
	}
	return prob
}

func (pNode *ProbNode) finishCheck(pTree *ProbTree) bool {
	/*
     * Check whether the whole space of pNode is scanned, i.e., all its children are finished.
	 */
	pNode.mutex.Lock()
	defer pNode.mutex.Unlock()
	for _, child := range pNode.children.Range() {
		if child != pTree.finishNode {  // some child is not finished.
			return false  
		}
	}
	pathLen := pNode.path.Len()
	if pathLen > 0 {  // this node is compressed, release the left-most dimension
		val := pNode.path.Back()
		pNode.path = pNode.path.Slice(0, pathLen - 1)
		pNode.divide = pNode.indices.Pop()
		pNode.children.Clear()
		pNode.children.Set(val, pTree.finishNode)
		return false
	} else {  // this node is probed
		return true
	}
}

func (pTree *ProbTree) finishCheckPath(nodesOnPath []*ProbNode) []*ProbNode {
	/*
     * Check whether the nodes on path are finished.
	 */
	nodesNum := len(nodesOnPath)
	for i := len(nodesOnPath) - 1; i > -1; i -- {
		node := nodesOnPath[i]
		if node.finishCheck(pTree) {
			nodesOnPath[i - 1].children.Replace(node, pTree.finishNode)
			nodesNum --
		}
	}
	return nodesOnPath[:nodesNum]
}

func (pTree *ProbTree) calculatePath(nodesOnPath []*ProbNode) {
	/*
	 * Re-calculate a and q of nodes in nodesOnPath
	 */
	// finish check
	aPrev := float32(0)
    // re-calculate a from root to leaf
	for _, node := range nodesOnPath {
		node.aCalculate(aPrev, pTree)
		aPrev = node.a
	}
    // re-calculate q from leaf to root
	for i := len(nodesOnPath) - 1; i > -1; i -- {
		node := nodesOnPath[i]
		node.qCalculate(pTree)
	}
} 

func (pTree *ProbTree) AddActive(addr net.IP) {
	/*
     * Use active addresses to update parameters in the model.
	 */
	addrBits := utils.NewBitsArray(32, []byte(addr))
	nowNode := pTree.rootNode
	nodesOnPath := make([]*ProbNode, 1)
	nodesOnPath[0] = nowNode
	for {
		nextEntry := addrBits.IndexAt(nowNode.divide)
		nowNode = nowNode.children.IndexAt(nextEntry)
		if nowNode == nil || nowNode == pTree.finishNode {
			break
		}
		nodesOnPath = append(nodesOnPath, nowNode)
	}
	for _, node := range nodesOnPath {
		node.nActive ++
	}
	pTree.calculatePath(nodesOnPath)
}

func (pTree *ProbTree) Generate() string {
	// Generate a prob IPv6 from the tree.
	newAddr := utils.NewBitsArray(32, make([]byte, 16))
	nowNode := pTree.rootNode
	nodesOnPath := make([]*ProbNode, 1)
	nodesOnPath[0] = nowNode
	remain := utils.Indices32(0xffffffff)
	for {
		// 1. fill the path
		indexArray := nowNode.indices.GetAll()
		remain.DelBatch(nowNode.indices)
		for i := uint8(0); i < nowNode.path.Len(); i ++ {
			val := nowNode.path.IndexAt(i)
			pos := indexArray[i]
			newAddr.Set(pos, val)
		}
		// 2. select next entry
		probs := nowNode.pCalculate(pTree)
		nextEntry := utils.RandBranchFloat(probs)
		remain.Del(nowNode.divide)
		newAddr.Set(nowNode.divide, nextEntry)
		// fmt.Println(remain.GetAll(), newAddr.ToIPv6())
		if len(remain.GetAll()) == 0 {
			break
		}
		// 3. recursion
		child := nowNode.children.IndexAt(nextEntry)
		if child == nil {
			// 4. generate the new address randomly
			if remain.Len() == 0 {
				nowNode.children.Set(nextEntry, pTree.finishNode)
			} else {
				newBits := utils.RandBits(remain.Len())
				remainArray := remain.GetAll()
				for i := uint8(0); i < newBits.Len(); i ++ {
					val := newBits.IndexAt(i)
					pos := remainArray[i]
					newAddr.Set(pos, val)
				}
				newLeaf := NewLeafProbNode(newBits, remain, pTree)
				nowNode.children.Set(nextEntry, newLeaf)
				nodesOnPath = append(nodesOnPath, newLeaf)
			}
			break
		} else {
			nowNode = child
			nodesOnPath = append(nodesOnPath, child)
		}
	}
	for _, node := range nodesOnPath {
		node.nProbes ++
	}
	nodesOnPath = pTree.finishCheckPath(nodesOnPath)
	pTree.calculatePath(nodesOnPath)
	return newAddr.ToIPv6()
}

func (pTree *ProbTree) recInit(addrs []utils.BitsArray, remain utils.Indices32) *ProbNode {
	/*
     * Find the dimension with the smallest entropy, and divide the node.
	 */
	// entropy aligns with remainArray
	remainArray := remain.GetAll()
	entropy := AddrsEntropy(addrs, remain)
	minEntropy := float64(3)
	minDimension := uint8(32)
	fixedDimension := make([]uint8, 0)
	// fixedDimension is 0-entorpy dimensions
	// minDimension is dimension with the smallest but > 0 entropy
	for i := 0; i < len(remainArray); i ++ {
		if entropy[i] == 0 {
			fixedDimension = append(fixedDimension, remainArray[i])
		} else if minEntropy > entropy[i] {
			minEntropy = entropy[i]
			minDimension = remainArray[i]
		}
	}
	path := utils.NewBitsArray(uint8(len(fixedDimension)), nil)
	for i := uint8(0); i < path.Len(); i ++ {
		path.Set(i, addrs[0].IndexAt(fixedDimension[i]))
	}

	var nowNode *ProbNode
	fixedIndices := utils.ToIndices(fixedDimension)
	remain.DelBatch(fixedIndices)
	if minDimension == 32 {  // there is only one address
		if path.Len() == 0 {
			for _, addrBits := range addrs {
				fmt.Println(addrBits.ToIPv6())
			}
			fmt.Println(fixedIndices, fixedDimension, remainArray, entropy[0])
		}
		minDimension = fixedIndices.Pop()  // use right-most dimension as divide
		nowNode = NewProbNode(path.Slice(0, path.Len() - 1), fixedIndices, minDimension)
		nowNode.children.Set(addrs[0].IndexAt(minDimension), pTree.finishNode)
	} else {
		remain.Del(minDimension)
		nowNode = NewProbNode(path, fixedIndices, minDimension)
		childrenAddrs := make([][]utils.BitsArray, 16)
		for _, addrBits := range addrs {
			entry := addrBits.IndexAt(minDimension)
			childrenAddrs[entry] = append(childrenAddrs[entry], addrBits)
		}
		for i, childAddrs := range childrenAddrs {
			if len(childAddrs) != 0 {
				if remain == 0 {
					nowNode.children.Set(uint8(i), pTree.finishNode)
				} else {
					nowNode.children.Set(uint8(i), pTree.recInit(childAddrs, remain))
				}
			}
		}
	}
	nowNode.nProbes = uint32(len(addrs))
	return nowNode
}

func (pTree *ProbTree) Init(ipStrArray []string) {
	/*
     * Initialize the tree with seed addresses.
	 */
	addrs := make([]utils.BitsArray, len(ipStrArray))
	for i := 0; i < len(addrs); i ++ {
		addrs[i] = utils.NewBitsArray(32, []byte(net.ParseIP(ipStrArray[i])))
	}
	remain := utils.Indices32(0xfffffffe)
	// all uni-cast IPv6 starts with 2
	pTree.rootNode.children.Set(2, pTree.recInit(addrs, remain))
	pTree.rootNode.nProbes = uint32(len(ipStrArray))
}

func (pTree *ProbTree) PrintInfo() {
	nowNode := pTree.rootNode.children.IndexAt(2)
	fmt.Println(nowNode.nActive, nowNode.nProbes, nowNode.divide)
	probs := nowNode.pCalculate(pTree)
	for i, child := range nowNode.children.Range() {
		if child == nil {
			fmt.Println(i, probs[i], 0)
		} else {
			fmt.Println(i, probs[i], child.q)
		}
	}
}

func (pTree *ProbTree) GetEstimation() float32 {
	return pTree.rootNode.q * 100
}