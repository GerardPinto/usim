#!/usr/bin/python
# Rijndael consists of the following operations:
# - an initial Round Key addition
# - 9 rounds, numbered 1-9, each consisting of
# -
# - a byte substitution transformation
# - a shift row transformation
# - a mix column transformation
# - a Round Key addition
# A final round (round 10) consisting of
# - a byte substitution transformation
# - a shift row transformation
# - a Round Key addition	
# Please refer spec for any changes
# This is code from milengae-spec in 3gpp. The 
# spec can be found in the folder of this project
class Milenage:

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

	roundKeys = [[[]]]

	# Rijndael S-box table
	Sbox =	[99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 
			202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 
			183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 
			4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 
			9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 
			83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 
			208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 
			81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 
			205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 
			96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 
			224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 
			231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 
			186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 
			112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 
			225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 
			140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22]

	# This array does the multiplication by x in GF(2^8)
	Xtime = [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 
			32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 
			64, 66, 68, 70, 72, 74, 76, 78, 80, 82, 84, 86, 88, 90, 92, 94, 
			96, 98, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126, 
			128, 130, 132, 134, 136, 138, 140, 142, 144, 146, 148, 150, 152, 154, 156, 158, 
			160, 162, 164, 166, 168, 170, 172, 174, 176, 178, 180, 182, 184, 186, 188, 190, 
			192, 194, 196, 198, 200, 202, 204, 206, 208, 210, 212, 214, 216, 218, 220, 222, 
			224, 226, 228, 230, 232, 234, 236, 238, 240, 242, 244, 246, 248, 250, 252, 254, 
			27, 25, 31, 29, 19, 17, 23, 21, 11, 9, 15, 13, 3, 1, 7, 5, 
			59, 57, 63, 61, 51, 49, 55, 53, 43, 41, 47, 45, 35, 33, 39, 37, 
			91, 89, 95, 93, 83, 81, 87, 85, 75, 73, 79, 77, 67, 65, 71, 69, 
			123, 121, 127, 125, 115, 113, 119, 117, 107, 105, 111, 109, 99, 97, 103, 101, 
			155, 153, 159, 157, 147, 145, 151, 149, 139, 137, 143, 141, 131, 129, 135, 133, 
			187, 185, 191, 189, 179, 177, 183, 181, 171, 169, 175, 173, 163, 161, 167, 165, 
			219, 217, 223, 221, 211, 209, 215, 213, 203, 201, 207, 205, 195, 193, 199, 197, 
			251, 249, 255, 253, 243, 241, 247, 245, 235, 233, 239, 237, 227, 225, 231, 229]   
	
	def __init__(self, Ki=[], RAND=[], OPc=[]):
		self.Ki = Ki
		self.RAND = RAND
		self.OPc = OPc

	def rijndaelKeySchedule(key):
		roundConst = 1

		# first round key equals key
		for index in range(16):
			roundKeys[0][index & 0x03][index>>2] = key[i]

		# now calculate round keys
		for i in range(1, 11):
			roundKeys[i][0][0] = S[roundKeys[i-1][1][3]] ^ roundKeys[i-1][0][0] ^ roundConst
			roundKeys[i][1][0] = S[roundKeys[i-1][2][3]] ^ roundKeys[i-1][1][0]
			roundKeys[i][2][0] = S[roundKeys[i-1][3][3]] ^ roundKeys[i-1][2][0]
			roundKeys[i][3][0] = S[roundKeys[i-1][0][3]] ^ roundKeys[i-1][3][0]
			for j in range(0,4):
				roundKeys[i][j][1] = roundKeys[i-1][j][1] ^ roundKeys[i][j][0]
				roundKeys[i][j][2] = roundKeys[i-1][j][2] ^ roundKeys[i][j][1]
				roundKeys[i][j][3] = roundKeys[i-1][j][3] ^ roundKeys[i][j][2]

			# update round constant
			roundConst = Xtime[roundConst]

	# Round key addition function
	def keyAdd(self, state, roundKeys, roundNo):
		for i in range(0,4):
			for j in range(0,4):
				state[i][j] ^= roundKeys[roundNo][i][j]

	# byte substitution transformation
	def byteSub(self, state):
		for i in range(0,4):
			for j in range(0,4):
				state[i][j] = S[state[i][j]]

	# Row shift transformation
	def shiftRow(self, state):
		temp = -1
		# left rotate row 1 by 1
		temp = state[1][0]
		state[1][0] = state[1][1]
		state[1][1] = state[1][2]
		state[1][2] = state[1][3]
		state[1][3] = temp
		# left rotate row 2 by 2
		temp = state[2][0]
		state[2][0] = state[2][2]
		state[2][2] = temp
		temp = state[2][1]
		state[2][1] = state[2][3]
		state[2][3] = temp
		# left rotate row 3 by 3
		temp = state[3][0]
		state[3][0] = state[3][3]
		state[3][3] = state[3][2]
		state[3][2] = state[3][1]
		state[3][1] = temp

	# mix column transformation
	def mixColumn(self, state):
		temp, tmp, tmp0 = -1
		# do one column at a time
		for i in range(0,4):
			temp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i]
			tmp0 = state[0][i]
			# Xtime array does multiply by x in GF2^8
			tmp = Xtime[state[0][i] ^ state[1][i]]
			state[0][i] ^= temp ^ tmp
			tmp = Xtime[state[1][i] ^ state[2][i]]
			state[1][i] ^= temp ^ tmp
			tmp = Xtime[state[2][i] ^ state[3][i]]
			state[2][i] ^= temp ^ tmp
			tmp = Xtime[state[3][i] ^ tmp0]
			state[3][i] ^= temp ^ tmp

	# Rijndael encrypt function takes 16 byte input
	# and creartes a 16 byte output, using round 
	# keys derived from 16 byte key Ki
	def rijndaelEncrypt(self, input, output):
		state[4][4]
		# initialise state array from input byte string
		for i in range(0, 16):
			state[i & 0x3][i>>2] = input[i]
		
		# add first round_key
		KeyAdd(state, roundKeys, 0)
		
		# do lots of full rounds
		for r in range(1,9):
			ByteSub(state)
			ShiftRow(state)
			MixColumn(state)
			KeyAdd(state, roundKeys, r)
		
		# final round
		byteSub(state)
		shiftRow(state)
		keyAdd(state, roundKeys, r)
		
		# produce output byte string from state array
		for i in range(0, 16):
			output[i] = state[i & 0x3][i>>2]

	# Computes network authentication code MAC-A from key K, 
	# random challenge RAND, sequence number SQN and 
	# authentication management field AMF.
	def f1(self):
		pass

	# Takes key Ki and random challenge RAND, and 
	# returns response RES, confidentiality key CK, 
	# integrity key IK and anonymity key AK.
	def f2345(self):
		pass