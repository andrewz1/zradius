package zdict

func init() {
	addAttr(40, "Acct-Status-Type", TypeInt)
	addAttr(41, "Acct-Delay-Time", TypeInt)
	addAttr(42, "Acct-Input-Octets", TypeInt)
	addAttr(43, "Acct-Output-Octets", TypeInt)
	addAttr(44, "Acct-Session-Id", TypeString)
	addAttr(45, "Acct-Authentic", TypeInt)
	addAttr(46, "Acct-Session-Time", TypeInt)
	addAttr(47, "Acct-Input-Packets", TypeInt)
	addAttr(48, "Acct-Output-Packets", TypeInt)
	addAttr(49, "Acct-Terminate-Cause", TypeInt)
	addAttr(50, "Acct-Multi-Session-Id", TypeString)
	addAttr(51, "Acct-Link-Count", TypeInt)
}
