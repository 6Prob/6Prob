package _6gen

import (
	"fmt"
	"math/rand"
)

type GenAlg struct {
	Seeds       []*Addr6
	Clusters    []*Addr6
	SeedRoot    *TreeNode
	ClusterRoot *TreeNode
	gran        int
	tight       bool
}

func InitGen(strAddrs []string, gran int, tight bool) *GenAlg {
	genAlg := &GenAlg{gran: gran, tight: tight}
	fmt.Println("Resolving address strings...")
	for _, strAddr := range strAddrs {
		newAddr := NewAddr6FromString(strAddr, gran)
		genAlg.Seeds = append(genAlg.Seeds, newAddr)
		genAlg.Clusters = append(genAlg.Clusters, newAddr)
	}
	fmt.Println("Constructing address trees...")
	genAlg.SeedRoot = InitTree(genAlg.Seeds)
	// genAlg.ClusterRoot = addr.InitTree(genAlg.Seeds)
	return genAlg
}

func (genAlg *GenAlg) growOneCluster(cluster *Addr6) *Addr6 {
	// Find the nearest seed but not covered by this cluster.
	coveredSet := genAlg.SeedRoot.GetCoveredSet(cluster)
	if len(coveredSet) == len(genAlg.Seeds) {
		fmt.Println(len(coveredSet), len(genAlg.Seeds))
		return cluster
	}
	nearestDis := AddrBitsLen
	var nearestAddrs []*Addr6
	for _, seed := range genAlg.Seeds {
		if _, exists := coveredSet[seed.Integer]; exists {
			continue
		} else {
			hmDis := GetHammingDistance(cluster, seed)
			if hmDis == nearestDis {
				nearestAddrs = append(nearestAddrs, seed)
			} else if hmDis < nearestDis {
				nearestDis = hmDis
				nearestAddrs = []*Addr6{seed}
			}
		}
	}
	// If there is a tie, find a random seed to grow.
	randIndex := rand.Intn(len(nearestAddrs))
	return CombineAddr(cluster, nearestAddrs[randIndex], genAlg.tight)
}

func (genAlg *GenAlg) GetSeedDensity(cluster *Addr6) float64 {
	if cluster == nil {
		return 0
	}
	// Seed density = # seeds / cluster range
	rangeCluster := cluster.GetFloatRange()
	nSeeds := len(genAlg.SeedRoot.GetCoverage(cluster))
	return float64(nSeeds) / rangeCluster
}

func (genAlg *GenAlg) GrowClusters(budget int, nProc int) []string {
	// Initialization
	candClusters := make([]*Addr6, len(genAlg.Clusters))
	densityArray := make([]float64, len(genAlg.Clusters))
	mutexChan := make(chan bool, 48)
	probeAddrSet := make(map[Uint128]bool)
	probeAddrArray := make([]string, 0)
	for i, cluster := range genAlg.Clusters {
		fmt.Printf("\r%d/%d...", i + 1, len(candClusters))
		probeAddrSet[cluster.ToInt128()] = true
		probeAddrArray = append(probeAddrArray, cluster.ToString())
		mutexChan <- true
		go func(i int) {
			newCluster := genAlg.growOneCluster(cluster)
			candClusters[i] = newCluster
			densityArray[i] = genAlg.GetSeedDensity(newCluster)
			<- mutexChan
		}(i)
	}

	for len(mutexChan) != 0 {}

	counter := 0
	for {
		// find the candidate with the most seed density
		electedDensity := float64(0)
		electedIndex := -1
		var electedCluster *Addr6
		oneForAll := false
		for i, cluster := range candClusters {
			if cluster == nil {
				continue
			}
			if cluster ==  genAlg.Clusters[i] {
				oneForAll = true
				break
			}
			if densityArray[i] > electedDensity {
				electedDensity = densityArray[i]
				electedIndex = i
				electedCluster = cluster
			} else if densityArray[i] == electedDensity {
				if cluster.Equal(electedCluster) {
					candClusters[i] = nil
					genAlg.Clusters[i] = nil
				}
			}
		}
		// all seeds are in one cluster
		if oneForAll {
			break
		}
		// genAlg.ClusterRoot.AddAddr(electedCluster)
		for _, addr := range electedCluster.ExpandRange() {
			if _, ok := probeAddrSet[addr.ToInt128()]; !ok {
				probeAddrArray = append(probeAddrArray, addr.ToString())
				probeAddrSet[addr.ToInt128()] = true
			}
		}
		genAlg.Clusters[electedIndex] = electedCluster
		fmt.Printf("\r%d New cluster density = %f. %d budget consumed.", counter, densityArray[electedIndex], len(probeAddrSet))
		if len(probeAddrSet) > budget {
			break
		}
		newCluster := genAlg.growOneCluster(genAlg.Clusters[electedIndex])
		candClusters[electedIndex] = newCluster
		densityArray[electedIndex] = genAlg.GetSeedDensity(newCluster)
		counter ++
	}
	return probeAddrArray[:budget]
}

func (genAlg *GenAlg) GetProbeAddr() []string {
	// probeAddrSet := genAlg.ClusterRoot.GetCoverage(nil)
	probeSet := make(map[Uint128]*Addr6)
	for _, cluster := range genAlg.Clusters {
		clusterAddrs := cluster.ExpandRange()
		for _, addr := range clusterAddrs {
			probeSet[addr.Integer] = addr
		}
	}
	var probeStr []string
	for _, addr := range probeSet {
		probeStr = append(probeStr, addr.ToString())
	}
	return probeStr
}
