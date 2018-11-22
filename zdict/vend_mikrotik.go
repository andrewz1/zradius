package zdict

// VendMikrotik - VendorID for Mikrotik
const VendMikrotik uint32 = 14988

func init() {
	addVSA(VendMikrotik, 1, "Mikrotik-Recv-Limit", TypeInt)
	addVSA(VendMikrotik, 2, "Mikrotik-Xmit-Limit", TypeInt)
	addVSA(VendMikrotik, 3, "Mikrotik-Group", TypeString)
	addVSA(VendMikrotik, 4, "Mikrotik-Wireless-Forward", TypeInt)
	addVSA(VendMikrotik, 5, "Mikrotik-Wireless-Skip-Dot1x", TypeInt)
	addVSA(VendMikrotik, 6, "Mikrotik-Wireless-Enc-Algo", TypeInt)
	addVSA(VendMikrotik, 7, "Mikrotik-Wireless-Enc-Key", TypeString)
	addVSA(VendMikrotik, 8, "Mikrotik-Rate-Limit", TypeString)
	addVSA(VendMikrotik, 9, "Mikrotik-Realm", TypeString)
	addVSA(VendMikrotik, 10, "Mikrotik-Host-IP", TypeIP4)
	addVSA(VendMikrotik, 11, "Mikrotik-Mark-Id", TypeString)
	addVSA(VendMikrotik, 12, "Mikrotik-Advertise-URL", TypeString)
	addVSA(VendMikrotik, 13, "Mikrotik-Advertise-Interval", TypeInt)
	addVSA(VendMikrotik, 14, "Mikrotik-Recv-Limit-Gigawords", TypeInt)
	addVSA(VendMikrotik, 15, "Mikrotik-Xmit-Limit-Gigawords", TypeInt)
	addVSA(VendMikrotik, 16, "Mikrotik-Wireless-PSK", TypeString)
	addVSA(VendMikrotik, 17, "Mikrotik-Total-Limit", TypeInt)
	addVSA(VendMikrotik, 18, "Mikrotik-Total-Limit-Gigawords", TypeInt)
	addVSA(VendMikrotik, 19, "Mikrotik-Address-List", TypeString)
	addVSA(VendMikrotik, 20, "Mikrotik-Wireless-MPKey", TypeString)
	addVSA(VendMikrotik, 21, "Mikrotik-Wireless-Comment", TypeString)
	addVSA(VendMikrotik, 22, "Mikrotik-Delegated-IPv6-Pool", TypeString)
	addVSA(VendMikrotik, 23, "Mikrotik-DHCP-Option-Set", TypeString)
	addVSA(VendMikrotik, 24, "Mikrotik-DHCP-Option-Param-STR1", TypeString)
	addVSA(VendMikrotik, 25, "Mikortik-DHCP-Option-Param-STR2", TypeString)
	addVSA(VendMikrotik, 26, "Mikrotik-Wireless-VLANID", TypeInt)
	addVSA(VendMikrotik, 27, "Mikrotik-Wireless-VLANID-Type", TypeInt)
	addVSA(VendMikrotik, 28, "Mikrotik-Wireless-Minsignal", TypeString)
	addVSA(VendMikrotik, 29, "Mikrotik-Wireless-Maxsignal", TypeString)
}
