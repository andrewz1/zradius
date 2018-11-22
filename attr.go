package zradius

import "github.com/andrewz1/zradius/zdict"

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
}
