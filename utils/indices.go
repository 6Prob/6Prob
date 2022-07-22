package utils

type Indices uint16

func (indices *Indices) Pos(i uint8) int8 {
	flag := Indices(1) << i
	if *indices & flag == 0 {
		return -1
	} else {
		pos := int8(0)
		for nowFlag := Indices(1); nowFlag < flag; nowFlag <<= 1 {
			if *indices & nowFlag != 0 {
				pos ++
			}
		}
		return pos
	}
}

func (indices *Indices) Add(i uint8) {
	*indices |= Indices(1) << i
}

func (indices *Indices) Del(i uint8) {
	*indices &= ^(Indices(1) << i)
}

func (indices *Indices) Has(i uint8) bool {
	if *indices & (1 << i) != 0 {
		return true
	} else {
		return false
	}
}

func (indices *Indices) Len() uint8 {
	_len := uint8(0)
	for i := uint8(0); i < 16; i ++ {
		if indices.Has(i) {
			_len ++
		}
	}
	return _len
}

func (indices *Indices) GetNil() []uint8 {
	var nilArray []uint8
	for i := uint8(0); i < 16; i ++ {
		if !indices.Has(i) {
			nilArray = append(nilArray, i)
		}
	}
	return nilArray
}

func (indices *Indices) GetMax() uint8 {
	max := uint8(0)
	for uint32(*indices) >= (1 << max) {
		max ++
	}
	return max - 1
}

type Indices32 uint32

func ToIndices(indexArray []uint8) Indices32 {
	newIndices := Indices32(0)
	for _, index := range indexArray {
		newIndices.Add(index)
	}
	return newIndices
}

func (indices *Indices32) Pos(i uint8) int8 {
	flag := Indices32(1) << i
	if *indices & flag == 0 {
		return -1
	} else {
		pos := int8(0)
		for nowFlag := Indices32(1); nowFlag < flag; nowFlag <<= 1 {
			if *indices & nowFlag != 0 {
				pos ++
			}
		}
		return pos
	}
}

func (indices *Indices32) Add(i uint8) {
	*indices |= Indices32(1) << i
}

func (indices *Indices32) AddBatch(addIndices Indices32) {
	*indices |= addIndices
}

func (indices *Indices32) Del(i uint8) {
	*indices &= ^(Indices32(1) << i)
}

func (indices *Indices32) DelBatch(delIndices Indices32) {
	*indices &= ^delIndices
}

func (indices *Indices32) Has(i uint8) bool {
	if *indices & (1 << i) != 0 {
		return true
	} else {
		return false
	}
}

func (indices *Indices32) Len() uint8 {
	_len := uint8(0)
	for i := uint8(0); i < 32; i ++ {
		if indices.Has(i) {
			_len ++
		}
	}
	return _len
}

func (indices *Indices32) GetNil() []uint8 {
	var nilArray []uint8
	for i := uint8(0); i < 32; i ++ {
		if !indices.Has(i) {
			nilArray = append(nilArray, i)
		}
	}
	return nilArray
}

func (indices *Indices32) GetAll() []uint8 {
	var allArray []uint8
	for i := uint8(0); i < 32; i ++ {
		if indices.Has(i) {
			allArray = append(allArray, i)
		}
	}
	return allArray
}

func (indices *Indices32) GetMax() uint8 {
	max := uint8(0)
	for uint64(*indices) >= (1 << max) {
		max ++
	}
	return max - 1
}

func (indices *Indices32) Pop() uint8 {
	max := indices.GetMax()
	indices.Del(max)
	return max
}