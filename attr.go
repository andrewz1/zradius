package zradius

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"hash"
	"net"

	"github.com/andrewz1/zradius/zdict"
)

// Attr - Radius attr storage
type Attr struct {
	typ   byte            // Attr type
	len   byte            // Attr len
	vid   uint32          // VendorID for VSA
	vtyp  byte            // VendorType for VSA
	vlen  byte            // VendorLen for VSA
	tag   byte            // Attr TAG for tagged atrtributess
	data  []byte          // raw attr data
	edata interface{}     // evaluated attr data
	atyp  *zdict.AttrData // Attr data from dictionary, nil if not found in dictionary
	dcr   bool            // "decrypted" flag for encrypted Attr
}

// decrypt User-Password attr
func (attr *Attr) decryptUsr(pkt *Packet) {
	var (
		l, i, j, s int
		sh         hash.Hash
		xor        []byte
		dst        []byte
	)

	if attr.dcr {
		return
	}
	defer func() {
		attr.dcr = true
	}()
	if l = len(attr.data); (l % 16) != 0 {
		return
	}
	sh = md5.New()
	sh.Write(pkt.secret)
	sh.Write(pkt.auth[:])
	xor = sh.Sum(nil)
	dst = make([]byte, l)
	for {
		for i = 0; i < 16; i++ {
			dst[j] = attr.data[j] ^ xor[i]
			j++
		}
		if j >= l {
			break
		}
		s = j - 16 // start byte
		sh.Reset()
		sh.Write(pkt.secret)
		sh.Write(attr.data[s:j])
		xor = sh.Sum(nil)
	}
	// cut pad zero bytes
	if s = bytes.IndexByte(dst, 0); s < 0 {
		s = l
	}
	attr.data = dst[:s]
}

// GetData - return raw attr data
func (attr *Attr) GetData() []byte {
	return attr.data
}

// GetEData - return evaluated attr data
func (attr *Attr) GetEData(pkt *Packet) interface{} {
	if attr.edata == nil {
		if attr.atyp == nil {
			attr.edata = attr.data
			return attr.edata
		}
		switch attr.atyp.Dtyp {
		case zdict.TypeString:
			if attr.atyp.Enc == zdict.EncUsr {
				attr.decryptUsr(pkt)
			}
			attr.edata = string(attr.data)
		case zdict.TypeInt:
			if len(attr.data) == 4 {
				attr.edata = binary.BigEndian.Uint32(attr.data)
			}
		case zdict.TypeIP4:
			if len(attr.data) == 4 {
				attr.edata = net.IPv4(attr.data[0], attr.data[1], attr.data[2], attr.data[3])
			}
		}
		if attr.edata == nil {
			attr.edata = attr.data
		}
	}
	return attr.edata
}

func (attr *Attr) updateLen() {
	if attr.typ == zdict.AttrVSA {
		attr.vlen = byte(len(attr.data) + 2)
		attr.len = attr.vlen + 6
	} else {
		attr.vlen = 0
		attr.len = byte(len(attr.data) + 2)
	}
}
