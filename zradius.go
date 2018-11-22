package zradius

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net"
	"sync"

	"github.com/andrewz1/zradius/zdict"
)

// основные константы из RFC
const (
	MaxPLen = 4096 // Максимальная длина пакета
	MinPLen = 20   // Минимальная длина пакета
)

type (
	// Attr - структура радиус-аттрибута
	Attr struct {
		typ   byte            // тип аттрибута
		len   byte            // длина атрибута из пакета
		vid   uint32          // VendorID для VSA
		vtyp  byte            // VendorType для VSA
		vlen  byte            // VendorLen для VSA
		data  []byte          // данные атрибута
		edata interface{}     // evaluated data
		atyp  *zdict.AttrData // данные из словаря атрибутов, nil если нет в словаре
	}

	// Packet - структура радиус-пакета
	Packet struct {
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

// разбор атрибута VSA
func (pkt *Packet) parseVSA(data []byte) error {
	var (
		vid    uint32
		vt, vl byte
		val    int
		bp, bl int
	)

	bl = len(data)
	if bl < 6 {
		return errors.New("Vendor len error")
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
			return errors.New("Vendor attr len error")
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

// RadRecvPkt - прием пакета из сокета
func RadRecvPkt(conn *net.UDPConn) (pkt *Packet, err error) {
	var (
		rbuf []byte
		num  int
		plen uint16
		addr *net.UDPAddr
	)

	rbuf = bufPool.Get().([]byte)
	defer bufPool.Put(rbuf)
	num, addr, err = conn.ReadFromUDP(rbuf)
	if err != nil {
		return nil, err
	}
	if num < MinPLen {
		return nil, fmt.Errorf("Packet too short, len: %d", num)
	}
	plen = binary.BigEndian.Uint16(rbuf[2:])
	if int(plen) > num {
		return nil, fmt.Errorf("Received packet too short, packet len: %d, recv: %d", plen, num)
	}
	pkt = &Packet{
		conn: conn,
		addr: addr,
		len:  plen,
		data: append([]byte(nil), rbuf[:plen]...),
	}
	return pkt, nil
}

// Decode - декодирование радиус-пакета
func (pkt *Packet) Decode() (err error) {
	var (
		at, al       byte
		bp, bl, alen int
	)

	bl = int(pkt.len)
	pkt.code = pkt.data[0]
	pkt.id = pkt.data[1]
	copy(pkt.auth[:], pkt.data[4:])
	bp += MinPLen
	bl -= MinPLen
	for bl >= 2 {
		at = pkt.data[bp]
		al = pkt.data[bp+1]
		bp += 2
		bl -= 2
		alen = int(al) - 2
		if alen < 0 || alen > bl {
			return fmt.Errorf("Attr len error, attr data len: %d, bytes left in packet: %d", alen, bl)
		}
		if at == zdict.AttrVSA { // Vendor-Specific
			err = pkt.parseVSA(pkt.data[bp : bp+alen])
			if err != nil {
				return err
			}
		} else { // обычный аттрибут
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

// Encode - encode radius packet
func (pkt *Packet) Encode() (err error) {
	var (
		sbuf       []byte
		bp, bl, al int
		a          *Attr
		hmd5       hash.Hash
	)

	sbuf = bufPool.Get().([]byte)
	defer bufPool.Put(sbuf)
	bl = len(sbuf)
	if bl < MinPLen {
		return fmt.Errorf("No space for minimum packet data: len = %d", bl)
	}
	sbuf[0] = pkt.code
	sbuf[1] = pkt.id
	copy(sbuf[4:], pkt.auth[:])
	bp += MinPLen
	bl -= MinPLen
	for _, a = range pkt.attr {
		if bl < 2 {
			return fmt.Errorf("No space for attr type: len = %d", bl)
		}
		sbuf[bp] = a.typ
		sbuf[bp+1] = a.len
		bp += 2
		bl -= 2
		al = int(a.len) - 2
		if a.typ == zdict.AttrVSA {
			if bl < 4 {
				return fmt.Errorf("No space for vendor ID: len = %d", bl)
			}
			binary.BigEndian.PutUint32(sbuf[bp:], a.vid)
			bp += 4
			bl -= 4
			if bl < 2 {
				return fmt.Errorf("No space for vendor type: len = %d", bl)
			}
			sbuf[bp] = a.vtyp
			sbuf[bp+1] = a.vlen
			bp += 2
			bl -= 2
			al = int(a.vlen) - 2
		}
		if al > 0 {
			if bl < al {
				return fmt.Errorf("No space for attr data: len = %d", bl)
			}
			copy(sbuf[bp:], a.data)
			bp += al
			bl -= al
		}
	}
	pkt.len = uint16(bp)
	binary.BigEndian.PutUint16(sbuf[2:], pkt.len)
	hmd5 = md5.New()
	hmd5.Write(sbuf[:bp])
	hmd5.Write(pkt.secret)
	copy(sbuf[4:], hmd5.Sum(nil))
	pkt.data = append([]byte(nil), sbuf[:bp]...)
	return nil
}

// RadNewPkt - создание нового пакета
func RadNewPkt(code byte) *Packet {
	return &Packet{
		code: code,
	}
}

// MakeReply - создание пакета в ответ на пакет
func (pkt *Packet) MakeReply(code byte) *Packet {
	return &Packet{
		conn:   pkt.conn,
		addr:   pkt.addr,
		code:   code,
		id:     pkt.id,
		auth:   pkt.auth,
		secret: pkt.secret,
	}
}

// SetSecret - установка секрета для пакета
func (pkt *Packet) SetSecret(secret []byte) {
	pkt.secret = secret
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
