package zradius

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"hash"
	"net"
	"sync"

	"github.com/andrewz1/zradius/zdict"
)

// Main constants from RFC
const (
	MinPLen = 20   // Min packet len
	MaxPLen = 4096 // Max packet len
)

var (
	bufPool = &sync.Pool{
		New: func() interface{} {
			return make([]byte, MaxPLen)
		},
	}
)

// Расшифровка User-Password аттрибута - нужно переделать - сейчас не используется
func decryptAttr(src []byte, pkt *Packet) (dst []byte) {
	var (
		l, i, j, s int
		sh         hash.Hash
		xor        []byte
	)

	l = len(src)
	if (l % 16) != 0 { // длина зашифрованного трибута должна быть кратна 16
		return nil
	}
	sh = md5.New() // secret md5 hash
	sh.Write(pkt.secret)
	sh.Write(pkt.auth[:])
	xor = sh.Sum(nil)
	dst = make([]byte, l)
	for {
		for i = 0; i < 16; i++ {
			dst[j] = src[j] ^ xor[i]
			j++
		}
		if j >= l {
			break
		}
		s = j - 16 // start byte
		sh.Reset()
		sh.Write(pkt.secret)
		sh.Write(src[s:j])
		xor = sh.Sum(nil)
	}
	l = bytes.IndexByte(dst, 0) // отрезаем нулевые байты в конце
	if l >= 0 {
		return dst[:l]
		// dst = append([]byte(nil), dst[:l]...)
	}
	return dst
}

// RadNewPkt - создание нового пакета
func RadNewPkt(code byte) *Packet {
	return &Packet{
		code: code,
	}
}

// String - печать пакета
func (pkt *Packet) String() string {
	var (
		r  = ""
		at *zdict.AttrData
	)

	r += fmt.Sprintf("Addr: %s\n", pkt.addr)
	r += fmt.Sprintf("Code: %d, ID: %d, Len: %d, Auth: %x\n", pkt.code, pkt.id, pkt.len, pkt.auth)
	for _, a := range pkt.attr {
		at = zdict.FindAllAttrBin(a.typ, a.vid, a.vtyp)
		if at != nil {
			r += fmt.Sprintf("%s", at.Name)
		} else {
			r += fmt.Sprintf("T: %d", a.typ)
		}
		r += fmt.Sprintf(", L: %d", a.len)
		if a.typ == zdict.AttrVSA {
			r += fmt.Sprintf(", VID: %d, VT: %d, VL: %d", a.vid, a.vtyp, a.vlen)
			if a.vlen > 0 {
				r += fmt.Sprintf(", DATA: %+v\n", a.GetEData(pkt))
			} else {
				r += fmt.Sprint("\n")
			}
		} else {
			if a.len > 0 {
				r += fmt.Sprintf(", DATA: %+v\n", a.GetEData(pkt))
			} else {
				r += fmt.Sprint("\n")
			}
		}
	}
	return r
}

// Send - отправка пакета в сеть
func (pkt *Packet) Send() (err error) {
	_, err = pkt.conn.WriteToUDP(pkt.data, pkt.addr)
	return err
}

// GetNasIP - возвращает NASIP как net.IP
func (pkt *Packet) GetNasIP() net.IP {
	return pkt.addr.IP
}

// GetNasU32 - возвращает NASIP как uint32
func (pkt *Packet) GetNasU32() uint32 {
	ip4 := pkt.addr.IP.To4()
	if ip4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip4)
}

// GetData - возвращает данные атрибута
func (attr *Attr) GetData() []byte {
	return attr.data
}

// GetEData - возвращает данные атрибута
func (attr *Attr) GetEData(pkt *Packet) interface{} {
	if attr.edata == nil {
		if attr.atyp == nil {
			attr.edata = attr.data
			return attr.edata
		}
		switch attr.atyp.Dtyp {
		case zdict.TypeString:
			if attr.atyp.Enc != zdict.EncNone {
				attr.edata = string(decryptAttr(attr.data, pkt))
			} else {
				attr.edata = string(attr.data)
			}
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

// GetCode - возвращает код пакета (тип)
func (pkt *Packet) GetCode() byte {
	return pkt.code
}

// GetAttrByName - поиск аттрибута в пакете по имени
func (pkt *Packet) GetAttrByName(name string) (attr *Attr, err error) {
	ad := zdict.FindAttrName(name)
	if ad == nil {
		return nil, fmt.Errorf("Unknown attribute: %s", name)
	}
	for _, at := range pkt.attr {
		if at.atyp == ad {
			return at, nil
		}
	}
	return nil, fmt.Errorf("Attribute %s not found", name)
}
