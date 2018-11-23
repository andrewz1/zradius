package zradius

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/andrewz1/zradius/zdict"
)

// Main constants from RFC
const (
	MinPLen = 20   // Min packet len
	MaxPLen = 4096 // Max packet len
)

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
