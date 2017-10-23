#!/usr/bin/python

import sys
from card.utils import *
from card.USIM import USIM

RAND = "00000000000000000000000000000000"
OPc = "3CE72BE7C01A305AE798B6C96C7506F3"
AMF = "8000"
SQN = "000000000000"
KI = "73C0987F885595CDC2733F5B98DF6F6A"

if __name__ == "__main__":
	u = USIM()
	u.dbg = 1
	if not u:
		print "Error opening USIM"
		exit(1)

	print "[+] Testing for random \t%s " % RAND
	print "[+] Derived operator code \t%s " % OPc
	print "[+] Private shared secret key \t%s " % KI
	print "[+] Sequence number \t%s " % SQN
	print "[+] Authentication management field \t%s " % AMF

	imsi = u.get_imsi()
	print "[+] Internation mobile subscriber identity \t%s " % imsi

	ak = u.get_ak(rand_bin, ki)	
	print "[+] Anonymity Key \t%s " % ak

	
	


	print "\n[+] UMTS Authentication"
	ret = u.authenticate(rand_bin, autn_bin, ctx='3G')

	if ret is None:
		print "[WNG] error in performing authentication"
		exit(1)

	if len(ret) == 1:
		print "AUTS:\t%s" % b2a_hex(byteToString(ret[0]))
	else:
		print "RES:\t%s" % b2a_hex(byteToString(ret[0]))
 		print "CK:\t%s" % b2a_hex(byteToString(ret[1]))
 		print "IK:\t%s" % b2a_hex(byteToString(ret[2]))
 		if len(ret) == 4:
 			print "Kc:\t%s" % b2a_hex(byteToString(ret[3]))