package maglev

import (
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"

	"github.com/dchest/siphash"
)

const (
	BigM           uint64 = 65537
	OffsetHashSeed uint64 = 0xdeadbabe
	SkipHashSeed   uint64 = 0xdeadbeef
)

//Maglev :
type Maglev struct {
	n           uint64 //size of VIP backends
	m           uint64 //sie of the lookup table
	permutation [][]uint64
	lookup      []int64
	nodeList    []string
	lock        *sync.RWMutex
}

//NewMaglev :
func NewMaglev(backends []string, m uint64) (*Maglev, error) {
	if !big.NewInt(0).SetUint64(m).ProbablyPrime(1) {
		return nil, errors.New("lookup table size is not a prime number")
	}
	mag := &Maglev{m: m, lock: &sync.RWMutex{}}
	if backends != nil {
		if err := mag.Set(backends); err != nil {
			return nil, err
		}
	}
	return mag, nil
}

//Add : Return nil if add success, otherwise return error
func (m *Maglev) Add(backend string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	for _, v := range m.nodeList {
		if v == backend {
			return errors.New("exist already")
		}
	}

	if m.m == m.n {
		return errors.New("number of backends would be greater than lookup table")
	}

	m.nodeList = append(m.nodeList, backend)
	m.n = uint64(len(m.nodeList))
	m.generatePopulation()
	m.populate()
	return nil
}

func (m *Maglev) AddOrDie(backend string) {
	if err := m.Add(backend); err != nil {
		panic(err)
	}
}

//Remove :
func (m *Maglev) Remove(backend string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	index := sort.SearchStrings(m.nodeList, backend)
	if index == len(m.nodeList) {
		return errors.New("fot found")
	}

	m.nodeList = append(m.nodeList[:index], m.nodeList[index+1:]...)

	m.n = uint64(len(m.nodeList))
	m.generatePopulation()
	m.populate()
	return nil
}

func (m *Maglev) RemoveOrDie(backend string) {
	if err := m.Remove(backend); err != nil {
		panic(err)
	}
}

func (m *Maglev) Set(backends []string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	n := uint64(len(backends))
	if m.m < n {
		return errors.New("number of backends is greater than lookup table")
	}
	m.nodeList = make([]string, n)
	copy(m.nodeList, backends) // Copy to avoid modifying orinal input afterwards
	m.n = n
	m.generatePopulation()
	m.populate()
	return nil
}

func (m *Maglev) SetOrDie(backends []string) {
	if err := m.Set(backends); err != nil {
		panic(err)
	}
}

func (m *Maglev) Clear() {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.nodeList = nil
	m.permutation = nil
	m.lookup = nil
}

func (m *Maglev) GetRawTable() []int64 {
	return m.lookup
}

func (m *Maglev) Dump() {
	fmt.Printf("nodeList.size: %d\n", len(m.nodeList))
	fmt.Printf("lookup.size: %d\n", len(m.lookup))
	for idx, u64 := range m.lookup {
		fmt.Printf("lookup[%010d]: %d\n", idx, u64)
	}
}

//Get :Get node name by object string.
func (m *Maglev) Get(obj string) (string, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	if len(m.nodeList) == 0 {
		return "", errors.New("Empty")
	}
	key := m.hashKey(obj)
	return m.nodeList[m.lookup[key%m.m]], nil
}

func (m *Maglev) GetOrDie(obj string) string {
	ret, err := m.Get(obj)
	if err != nil {
		panic(err)
	}
	return ret
}

func (m *Maglev) hashKey(obj string) uint64 {
	return siphash.Hash(OffsetHashSeed, 0, []byte(obj))
}

func (m *Maglev) generatePopulation() {
	m.permutation = nil
	if len(m.nodeList) == 0 {
		return
	}

	sort.Strings(m.nodeList)

	for i := 0; i < len(m.nodeList); i++ {
		bData := []byte(m.nodeList[i])

		offset := siphash.Hash(OffsetHashSeed, 0, bData) % m.m
		skip := (siphash.Hash(SkipHashSeed, 0, bData) % (m.m - 1)) + 1

		iRow := make([]uint64, m.m)
		var j uint64
		for j = 0; j < m.m; j++ {
			iRow[j] = (offset + uint64(j)*skip) % m.m
		}

		m.permutation = append(m.permutation, iRow)
	}
}

func (m *Maglev) populate() {
	if len(m.nodeList) == 0 {
		return
	}

	var i, j uint64
	next := make([]uint64, m.n)
	entry := make([]int64, m.m)
	for j = 0; j < m.m; j++ {
		entry[j] = -1
	}

	var n uint64

	for { //true
		for i = 0; i < m.n; i++ {
			c := m.permutation[i][next[i]]
			for entry[c] >= 0 {
				next[i] = next[i] + 1
				c = m.permutation[i][next[i]]
			}

			entry[c] = int64(i)
			next[i] = next[i] + 1
			n++

			if n == m.m {
				m.lookup = entry
				return
			}
		}

	}

}
