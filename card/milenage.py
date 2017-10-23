
class MilenageAlgo:

	AK = None
	CK = None
	IK = None
	XRES = None
	Ki = None
	RAND = None
	OPc = None
	R = [0x40, 0x0, 0x20, 0x40, 0x60]
	C = ["00000000000000000000000000000000", 
	"00000000000000000000000000000001", 
	"00000000000000000000000000000002", 
	"00000000000000000000000000000004", 
	"00000000000000000000000000000008",
	]	

	def __init__(self, Ki=[], RAND=[], OPc=[]):
		self.Ki = Ki
		self.RAND = RAND
		self.OPc = OPc

	# Computes network authentication code MAC-A from key K, 
	# random challenge RAND, sequence number SQN and 
	# authentication management field AMF.
	def f1():
		pass

	# Takes key Ki and random challenge RAND, and 
	# returns response RES, confidentiality key CK, 
	# integrity key IK and anonymity key AK.
	def f2345():
		pass


