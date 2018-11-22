package zdict

func init() {
	addAttr2(64, "Tunnel-Type", TypeInt, true, EncNone)
	addAttr2(65, "Tunnel-Medium-Type", TypeInt, true, EncNone)
	addAttr2(66, "Tunnel-Client-Endpoint", TypeString, true, EncNone)
	addAttr2(67, "Tunnel-Server-Endpoint", TypeString, true, EncNone)

	addAttr2(69, "Tunnel-Password", TypeString, true, EncTun)

	addAttr2(81, "Tunnel-Private-Group-Id", TypeString, true, EncNone)
	addAttr2(82, "Tunnel-Assignment-Id", TypeString, true, EncNone)
	addAttr2(83, "Tunnel-Preference", TypeInt, true, EncNone)

	addAttr2(90, "Tunnel-Client-Auth-Id", TypeString, true, EncNone)
	addAttr2(91, "Tunnel-Server-Auth-Id", TypeString, true, EncNone)
}
