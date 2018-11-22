package zdict

func init() {
	addAttr(52, "Acct-Input-Gigawords", TypeInt)
	addAttr(53, "Acct-Output-Gigawords", TypeInt)

	addAttr(55, "Event-Timestamp", TypeDate)

	addAttr(70, "ARAP-Password", TypeRaw)
	addAttr(71, "ARAP-Features", TypeRaw)
	addAttr(72, "ARAP-Zone-Access", TypeInt)
	addAttr(73, "ARAP-Security", TypeInt)
	addAttr(74, "ARAP-Security-Data", TypeString)
	addAttr(75, "Password-Retry", TypeInt)
	addAttr(76, "Prompt", TypeInt)
	addAttr(77, "Connect-Info", TypeString)
	addAttr(78, "Configuration-Token", TypeString)
	addAttr(79, "EAP-Message", TypeRaw)
	addAttr(80, "Message-Authenticator", TypeRaw)

	addAttr(84, "ARAP-Challenge-Response", TypeRaw)
	addAttr(85, "Acct-Interim-Interval", TypeInt)

	addAttr(87, "NAS-Port-Id", TypeString)
	addAttr(88, "Framed-Pool", TypeString)
}
