package zradius

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash"
	"net"
	"sync"
	"sync/atomic"

	"github.com/andrewz1/zradius/zdict"
)

// Packet - Radius packet storage
type Packet struct {
	conn   *net.UDPConn // соединение через которое этот пакет был получен
	addr   *net.UDPAddr // откуда этот пакет был получен или куда должен быть отправлен ответ
	code   byte         // radius code, Request, Accept, Reject and etc.
	id     byte         // radius id
	len    uint16       // длина из пакета
	auth   [16]byte     // авторизационные данные из пакета
	attr   []*Attr      // слайс с аттрибутами
	secret []byte       // секрет для этого пакета
	data   []byte       // raw packet data
	ctx    interface{}  // user context
}

var (
	pbPool sync.Pool
	radID  uint32
)

func getPBuf() []byte {
	var v interface{}
	if v = pbPool.Get(); v != nil {
		return v.([]byte)[:MaxPLen]
	}
	return make([]byte, MaxPLen)
}

func putPBuf(b []byte) {
	pbPool.Put(b)
}

// RadNew - create new packet with given code
func RadNew(code byte) *Packet {
	return &Packet{
		code: code,
		id:   byte(atomic.AddUint32(&radID, 1)),
	}
}

// RadRecv - receive Radius packet from conn and check packet len
func RadRecv(conn *net.UDPConn) (pkt *Packet, err error) {
	var (
		buf  []byte
		num  int
		pl   uint16
		addr *net.UDPAddr
	)

	buf = getPBuf()
	defer putPBuf(buf)
	if num, addr, err = conn.ReadFromUDP(buf); err != nil {
		return nil, err
	}
	if num < MinPLen {
		return nil, fmt.Errorf("Packet too short, len: %d", num)
	}
	pl = binary.BigEndian.Uint16(buf[2:])
	if int(pl) > num {
		return nil, fmt.Errorf("Received packet too short, packet len: %d, recv: %d", pl, num)
	}
	pkt = &Packet{
		conn: conn,
		addr: addr,
		len:  pl,
		data: append([]byte(nil), buf[:pl]...),
	}
	return pkt, nil
}

// parse VSA attr
func (pkt *Packet) parseVSA(data []byte) error {
	var (
		bp, bl int    // buffer pointer and left
		val    int    // vendor attr data len
		vid    uint32 // vendor ID
		vt, vl byte   // vendor type and len
	)

	bl = len(data)
	if bl < 6 {
		return fmt.Errorf("VSA len minimal is 6, len = %d", bl)
	}
	vid = binary.BigEndian.Uint32(data[bp:])
	bp += 4
	bl -= 4
	for bl >= 2 {
		vt = data[bp]
		vl = data[bp+1]
		bp += 2
		bl -= 2
		val = int(vl) - 2
		if val > bl {
			return fmt.Errorf("Vendor attr len error, buffer len = %d, attr len = %d", bl, val)
		}
		attr := &Attr{
			typ:  zdict.AttrVSA,
			len:  vl + 6,
			vid:  vid,
			vtyp: vt,
			vlen: vl,
			data: data[bp : bp+val],
			atyp: zdict.FindVSABin(vid, vt),
		}
		pkt.attr = append(pkt.attr, attr)
		bp += val
		bl -= val
	}
	return nil
}

// Decode - decode Radius packet from pkt.data
func (pkt *Packet) Decode() (err error) {
	var (
		bp, bl int  // buffer pointer and buffer left
		alen   int  // attr data len
		at, al byte // attr type and len (raw)
	)

	bl = len(pkt.data)
	pkt.code = pkt.data[0]
	pkt.id = pkt.data[1]
	pkt.len = binary.BigEndian.Uint16(pkt.data[2:]) // overwrite
	copy(pkt.auth[:], pkt.data[4:])
	bp += MinPLen
	bl -= MinPLen
	// data above is a minimal Radius packet - so don't need to check for overflow
	for bl >= 2 {
		at = pkt.data[bp]
		al = pkt.data[bp+1]
		bp += 2
		bl -= 2
		alen = int(al) - 2
		if alen < 0 || alen > bl {
			return fmt.Errorf("Attr len error, attr data len: %d, bytes left in buffer: %d", alen, bl)
		}
		if at == zdict.AttrVSA { // VSA
			if err = pkt.parseVSA(pkt.data[bp : bp+alen]); err != nil {
				return err
			}
		} else { // Plain attr
			attr := &Attr{
				typ:  at,
				len:  al,
				data: pkt.data[bp : bp+alen],
				atyp: zdict.FindAttrBin(at),
			}
			pkt.attr = append(pkt.attr, attr)
		}
		bp += alen
		bl -= alen
	}
	return nil
}

// Encode - encode Radius packet to pkt.data
func (pkt *Packet) Encode(newPkt bool) (err error) {
	var (
		buf    []byte
		bp, bl int
		alen   int
		a      *Attr
		hmd    hash.Hash
	)

	buf = getPBuf()
	defer putPBuf(buf)
	bl = len(buf)
	buf[0] = pkt.code
	buf[1] = pkt.id
	if newPkt {
		alen, err = rand.Read(buf[4:20]) // reuse alen
		if err != nil {
			return err
		}
		if alen != 16 {
			return fmt.Errorf("Random read error, request 16 bytes, got %d", alen)
		}
	} else {
		copy(buf[4:], pkt.auth[:]) // this is old packet data
	}
	bp += MinPLen
	bl -= MinPLen
	for _, a = range pkt.attr {
		if bl < 2 {
			return fmt.Errorf("No space in buffer: used = %d, left = %d", bp, bl)
		}
		buf[bp] = a.typ
		buf[bp+1] = a.len
		bp += 2
		bl -= 2
		alen = int(a.len) - 2
		if a.typ == zdict.AttrVSA {
			if bl < 6 {
				return fmt.Errorf("No space in buffer: used = %d, left = %d", bp, bl)
			}
			binary.BigEndian.PutUint32(buf[bp:], a.vid)
			bp += 4
			bl -= 4
			buf[bp] = a.vtyp
			buf[bp+1] = a.vlen
			bp += 2
			bl -= 2
			alen = int(a.vlen) - 2
		}
		if alen > 0 {
			if bl < alen {
				return fmt.Errorf("No space in buffer: used = %d, left = %d", bp, bl)
			}
			copy(buf[bp:], a.data)
			bp += alen
			bl -= alen
		}
	}
	pkt.len = uint16(bp)
	binary.BigEndian.PutUint16(buf[2:], pkt.len)
	if !newPkt {
		hmd = md5.New()
		hmd.Write(buf[:bp])
		hmd.Write(pkt.secret)
		copy(buf[4:], hmd.Sum(nil))
	}
	pkt.data = append([]byte(nil), buf[:bp]...)
	return nil
}

// RadReply - create reply Radius packet
func (pkt *Packet) RadReply(code byte) *Packet {
	return &Packet{
		conn:   pkt.conn,
		addr:   pkt.addr,
		code:   code,
		id:     pkt.id,
		auth:   pkt.auth,
		secret: pkt.secret,
	}
}

// SetSecret - set Radius shared secret for packet
func (pkt *Packet) SetSecret(s []byte) {
	pkt.secret = s
}

// SetSecretStr - set Radius shared secret for packet
func (pkt *Packet) SetSecretStr(s string) {
	pkt.secret = []byte(s)
}

// SetAddr - set Addr in Packet
func (pkt *Packet) SetAddr(addr *net.UDPAddr) {
	pkt.addr = addr
}

// SetConn - set Conn in Packet
func (pkt *Packet) SetConn(conn *net.UDPConn) {
	pkt.conn = conn
}

// GetCode - get Radius packet code
func (pkt *Packet) GetCode() byte {
	return pkt.code
}

// GetAttr - search attribute by name
func (pkt *Packet) GetAttr(name string) *Attr {
	var (
		ad   *zdict.AttrData
		attr *Attr
	)

	if ad = zdict.FindAttrName(name); ad == nil {
		return nil
	}
	for _, attr = range pkt.attr {
		if attr.atyp == ad {
			if attr.atyp.Enc == zdict.EncUsr {
				attr.decryptUsr(pkt)
			}
			return attr
		}
	}
	return nil
}

// AddAttrRaw - add raw Attr to packet
func (pkt *Packet) AddAttrRaw(name string, val []byte) error {
	var (
		ad   *zdict.AttrData
		attr *Attr
	)

	if ad = zdict.FindAttrName(name); ad == nil {
		return fmt.Errorf("Attribute %s not found", name)
	}
	attr = &Attr{
		typ:  ad.Typ,
		vid:  ad.Vid,
		vtyp: ad.Vtyp,
		data: val,
		atyp: ad,
	}
	attr.updateLen()
	pkt.attr = append(pkt.attr, attr)
	return nil
}

// MustAddAttrRaw - add raw Attr to packet
func (pkt *Packet) MustAddAttrRaw(name string, val []byte) {
	if err := pkt.AddAttrRaw(name, val); err != nil {
		panic(err)
	}
}

// AddAttrStr - add string Attr to packet
func (pkt *Packet) AddAttrStr(name, val string) error {
	return pkt.AddAttrRaw(name, []byte(val))
}

// MustAddAttrStr - add string Attr to packet
func (pkt *Packet) MustAddAttrStr(name, val string) {
	if err := pkt.AddAttrStr(name, val); err != nil {
		panic(err)
	}
}

// AddAttrInt - add int Attr to packet
func (pkt *Packet) AddAttrInt(name string, val uint32) error {
	var t [4]byte

	binary.BigEndian.PutUint32(t[:], val)
	return pkt.AddAttrRaw(name, t[:])
}

// MustAddAttrInt - add int Attr to packet
func (pkt *Packet) MustAddAttrInt(name string, val uint32) {
	if err := pkt.AddAttrInt(name, val); err != nil {
		panic(err)
	}
}

// AddAttrIP4 - add IPv4 Attr to packet
func (pkt *Packet) AddAttrIP4(name string, val net.IP) error {
	t := val.To4()
	if t == nil {
		return fmt.Errorf("Argument is not IPv4")
	}
	return pkt.AddAttrRaw(name, t)
}

// MustAddAttrIP4 - add IPv4 Attr to packet
func (pkt *Packet) MustAddAttrIP4(name string, val net.IP) {
	if err := pkt.AddAttrIP4(name, val); err != nil {
		panic(err)
	}
}
