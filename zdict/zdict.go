package zdict

import (
	"strings"
	"sync"
)

// Encryprion type for Attr
const (
	EncNone int = iota // No encryption
	EncUsr             // User-Password encryption
	EncTun             // Tunnel-Password encryption
	EncAsc             // Ascend’s proprietary encryption
)

// Data type for Attr
const (
	TypeRaw    int = iota // byte slice
	TypeString            // string
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
)

// RFC constants
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

// AttrData - dictionary entry for Attr
type AttrData struct {
	Name string // Attr name
	Typ  byte   // Attr type
	Vid  uint32 // VendorID if Typ == AttrVSA
	Vtyp byte   // VendorType if Typ == AttrVSA
	Dtyp int    // Attr data type
	Tag  bool   // Is Attr tagged
	Enc  int    // Encription type
}

var (
	strMap sync.Map // map by name
	binMap sync.Map // map by attr data
)

// makeKey - generate key for binary map
func makeKey(typ byte, vid uint32, vtyp byte) uint64 {
	if typ != AttrVSA {
		return uint64(typ)
	}
	return (uint64(vid) << 16) | (uint64(vtyp) << 8) | uint64(typ)
}

// add Attr to maps
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
	binMap.Store(bkey, adata)
	strMap.Store(skey, adata)
}

// add VSA to dictionary
func addVSA(vid uint32, vtyp byte, name string, dtyp int) {
	addAttrGeneric(AttrVSA, vid, vtyp, name, dtyp, false, EncNone)
}

// add VSA with tag and enc to dictionary
func addVSA2(vid uint32, vtyp byte, name string, dtyp int, tag bool, enc int) {
	addAttrGeneric(AttrVSA, vid, vtyp, name, dtyp, tag, enc)
}

// add plain Attr to dictionary
func addAttr(typ byte, name string, dtyp int) {
	addAttrGeneric(typ, 0, 0, name, dtyp, false, EncNone)
}

// add plain Attr with tag and enc
func addAttr2(typ byte, name string, dtyp int, tag bool, enc int) {
	addAttrGeneric(typ, 0, 0, name, dtyp, tag, enc)
}

// FindAttrBin - find plain Attr by type
func FindAttrBin(typ byte) *AttrData {
	return FindAllAttrBin(typ, 0, 0)
}

// FindVSABin - find VSA by VendorID and VendorType
func FindVSABin(vid uint32, vtyp byte) *AttrData {
	return FindAllAttrBin(AttrVSA, vid, vtyp)
}

// FindAllAttrBin - find any Attr by binary params
func FindAllAttrBin(typ byte, vid uint32, vtyp byte) *AttrData {
	k := makeKey(typ, vid, vtyp)
	v, ok := binMap.Load(k)
	if !ok {
		return nil
	}
	return v.(*AttrData)
}

// FindAttrName - find any attr by name
func FindAttrName(name string) *AttrData {
	k := strings.ToLower(name)
	v, ok := strMap.Load(k)
	if !ok {
		return nil
	}
	return v.(*AttrData)
}
