package zdict

import (
	"strings"
	"sync"
)

// Тип шифрования для аттрибута
const (
	EncNone int = iota // No encryption
	EncUsr             // User-Password encryption
	EncTun             // Tunnel-Password encryption
	EncAsc             // Ascend’s proprietary encryption
)

// Тип данных для аттрибута
const (
	TypeString int = iota // string
	TypeIP4               // ip addr
	TypeIP4Pfx            // 6 bytes
	TypeInt               // uint32
	TypeInt64             // uint64
	TypeDate              // unix time 32 bit
	TypeIfID              // 8 bytes
	TypeIP6               // 16 bytes
	TypeIP6Pfx            // 18 bytes
	TypeByte              // one byte
	TypeEth               // 6 bytes, MAC
	TypeShort             // uint16
	TypeSInt              // signed int
	TypeVSA               // VSA
	TypeRaw               // byte slice
)

// Различные константы
const (
	AttrVSA = 26

	// RFC3575
	AccessRequest      = 1
	AccessAccept       = 2
	AccessReject       = 3
	AccountingRequest  = 4
	AccountingResponse = 5
	AccountingStatus   = 6
	PasswordRequest    = 7
	PasswordAck        = 8
	PasswordReject     = 9
	AccountingMessage  = 10
	AccessChallenge    = 11
	StatusServer       = 12
	StatusClient       = 13
	DisconnectRequest  = 40
	DisconnectACK      = 41
	DisconnectNAK      = 42
	CoARequest         = 43
	CoAACK             = 44
	CoANAK             = 45
)

// AttrData - структура для хранения характеристик аттрибута в словаре
type AttrData struct {
	Name string // имя аттрибута
	Typ  byte   // тип аттрибута
	Vid  uint32 // VendorID если Typ == 26
	Vtyp byte   // VendorType если Typ == 26

	Dtyp int  // тип данных
	Tag  bool // тэгированный аттрибут или нет
	Enc  int  // тип шифрования
}

// мапа для поиска по имени
type attrBinMap struct {
	sync.RWMutex
	m map[string]*AttrData
}

// мапа для поиска по данным из пакета
type attrStrMap struct {
	sync.RWMutex
	m map[uint64]*AttrData
}

var (
	s2bMap = attrBinMap{m: map[string]*AttrData{}}
	b2sMap = attrStrMap{m: map[uint64]*AttrData{}}
)

// makeKey - функция генерации ключа для map-ы strMap из данных аттрибута
func makeKey(typ byte, vid uint32, vtyp byte) uint64 {
	if typ != AttrVSA {
		return uint64(typ)
	}
	return (uint64(vid) << 16) | (uint64(vtyp) << 8) | uint64(typ)
}

// добавление аттрибута в базу
func addAttrGeneric(typ byte, vid uint32, vtyp byte, name string, dtyp int, tag bool, enc int) {
	skey := strings.ToLower(name)
	bkey := makeKey(typ, vid, vtyp)
	adata := &AttrData{
		Name: name,
		Typ:  typ,
		Vid:  vid,
		Vtyp: vtyp,
		Dtyp: dtyp,
		Tag:  tag,
		Enc:  enc,
	}
	b2sMap.Lock()
	b2sMap.m[bkey] = adata
	b2sMap.Unlock()
	s2bMap.Lock()
	s2bMap.m[skey] = adata
	s2bMap.Unlock()
}

func addVSA(vid uint32, vtyp byte, name string, dtyp int) {
	addAttrGeneric(AttrVSA, vid, vtyp, name, dtyp, false, EncNone)
}

func addVSA2(vid uint32, vtyp byte, name string, dtyp int, tag bool, enc int) {
	addAttrGeneric(AttrVSA, vid, vtyp, name, dtyp, tag, enc)
}

func addAttr(typ byte, name string, dtyp int) {
	addAttrGeneric(typ, 0, 0, name, dtyp, false, EncNone)
}

func addAttr2(typ byte, name string, dtyp int, tag bool, enc int) {
	addAttrGeneric(typ, 0, 0, name, dtyp, tag, enc)
}

// FindAttrBin - поиск обычного атрибута по типу
func FindAttrBin(typ byte) (ret *AttrData) {
	return FindAllAttrBin(typ, 0, 0)
}

// FindVSABin - поиск VSA по VendorID и VendorType
func FindVSABin(vid uint32, vtyp byte) (ret *AttrData) {
	return FindAllAttrBin(AttrVSA, vid, vtyp)
}

// FindAllAttrBin - поиск любого атрибута по всем параметрам
func FindAllAttrBin(typ byte, vid uint32, vtyp byte) (ret *AttrData) {
	k := makeKey(typ, vid, vtyp)
	b2sMap.RLock()
	ret, ok := b2sMap.m[k]
	b2sMap.RUnlock()
	if !ok {
		return nil
	}
	return ret
}

// FindAttrName - поиск аттрибута по имени
func FindAttrName(name string) (ret *AttrData) {
	k := strings.ToLower(name)
	s2bMap.RLock()
	ret, ok := s2bMap.m[k]
	s2bMap.RUnlock()
	if !ok {
		return nil
	}
	return ret
}
