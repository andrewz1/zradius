package zdict

// VendWISPR - VendorID for WISPR
const VendWISPR uint32 = 14122

func init() {
	addVSA(VendWISPR, 1, "WISPr-Location-ID", TypeString)
	addVSA(VendWISPR, 2, "WISPr-Location-Name", TypeString)
	addVSA(VendWISPR, 3, "WISPr-Logoff-URL", TypeString)
	addVSA(VendWISPR, 4, "WISPr-Redirection-URL", TypeString)
	addVSA(VendWISPR, 5, "WISPr-Bandwidth-Min-Up", TypeInt)
	addVSA(VendWISPR, 6, "WISPr-Bandwidth-Min-Down", TypeInt)
	addVSA(VendWISPR, 7, "WISPr-Bandwidth-Max-Up", TypeInt)
	addVSA(VendWISPR, 8, "WISPr-Bandwidth-Max-Down", TypeInt)
	addVSA(VendWISPR, 9, "WISPr-Session-Terminate-Time", TypeString)
	addVSA(VendWISPR, 10, "WISPr-Session-Terminate-End-Of-Day", TypeString)
	addVSA(VendWISPR, 11, "WISPr-Billing-Class-Of-Service", TypeString)
}
