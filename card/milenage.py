#!/usr/bin/python
from binascii import *
from utils import *

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

	KI = []
	AK = []
	CK = []
	IK = []
	RES = []
	Ki = []
	RAND = []
	OPc = []
	SQN = []
	AMF = []
	R = [0x40, 0x0, 0x20, 0x40, 0x60]
	C = [0, 1, 2, 4, 8]

	roundKeys = [[[0]*4]*4]*11

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
	
	def __init__(self, ki=[], rand=[], opc=[], sqn=[], amf=[]):
		self.KI = ki
		self.RAND = rand
		self.OPc = opc
		self.SQN = sqn
		self.AMF = amf
		self.RES = [0]*8
		self.KI = [0]*16		
		self.CK = [0]*16
		self.IK = [0]*16
		self.AK = [0]*6
		

	def rijndaelKeySchedule(self, key):
		roundConst = 1
		# first round key equals key
		for index in range(16):
			self.roundKeys[0][index & 0x03][index>>2] = key[index]

		# now calculate round keys
		for i in range(1, 11):
			self.roundKeys[i][0][0] = self.Sbox[self.roundKeys[i-1][1][3]] ^ self.roundKeys[i-1][0][0] ^ roundConst
			self.roundKeys[i][1][0] = self.Sbox[self.roundKeys[i-1][2][3]] ^ self.roundKeys[i-1][1][0]
			self.roundKeys[i][2][0] = self.Sbox[self.roundKeys[i-1][3][3]] ^ self.roundKeys[i-1][2][0]
			self.roundKeys[i][3][0] = self.Sbox[self.roundKeys[i-1][0][3]] ^ self.roundKeys[i-1][3][0]
			for j in range(0,4):
				self.roundKeys[i][j][1] = self.roundKeys[i-1][j][1] ^ self.roundKeys[i][j][0]
				self.roundKeys[i][j][2] = self.roundKeys[i-1][j][2] ^ self.roundKeys[i][j][1]
				self.roundKeys[i][j][3] = self.roundKeys[i-1][j][3] ^ self.roundKeys[i][j][2]

			# update round constant
			roundConst = self.Xtime[roundConst]

	# Round key addition function
	def keyAdd(self, state, roundKeys, roundNo):
		for i in range(0,4):
			for j in range(0,4):
				state[i][j] ^= roundKeys[roundNo][i][j]

	# byte substitution transformation
	def byteSub(self, state):
		for i in range(0,4):
			for j in range(0,4):
				state[i][j] = self.Sbox[state[i][j]]

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
		temp, tmp, tmp0 = -1, -1, -1
		# do one column at a time
		for i in range(0,4):
			temp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i]
			tmp0 = state[0][i]
			# Xtime array does multiply by x in GF2^8
			tmp = self.Xtime[state[0][i] ^ state[1][i]]
			state[0][i] ^= temp ^ tmp
			tmp = self.Xtime[state[1][i] ^ state[2][i]]
			state[1][i] ^= temp ^ tmp
			tmp = self.Xtime[state[2][i] ^ state[3][i]]
			state[2][i] ^= temp ^ tmp
			tmp = self.Xtime[state[3][i] ^ tmp0]
			state[3][i] ^= temp ^ tmp

	# Rijndael encrypt function takes 16 byte input
	# and creartes a 16 byte output, using round 
	# keys derived from 16 byte key Ki
	def rijndaelEncrypt(self, input, output):
		state = [[0]*4]*4
		# initialise state array from input byte string
		for i in range(0, 16):
			state[i & 0x3][i>>2] = input[i]
		
		# add first round_key
		self.keyAdd(state, self.roundKeys, 0)
		
		# do lots of full rounds
		for r in range(1,9):
			self.byteSub(state)
			self.shiftRow(state)
			self.mixColumn(state)
			self.keyAdd(state, self.roundKeys, r)
		
		# final round
		self.byteSub(state)
		self.shiftRow(state)
		self.keyAdd(state, self.roundKeys, r)
		
		# produce output byte string from state array
		for i in range(0, 16):
			output[i] = state[i & 0x3][i>>2]

	# Computes network authentication code MAC-A from key K, 
	# random challenge RAND, sequence number SQN and 
	# authentication management field AMF.
	def f1(self):
		temp = [0]*16
		rijndaelInput = [0]*16
		in1 = [0]*16
		out1 = [0]*16
		mac_a = [0]*8

		self.rijndaelKeySchedule(self.KI)

		# Here compute OPc if OP is given
		
		for i in range(0, 16):			
			rijndaelInput[i] = self.RAND[i] ^ self.OPc[i]
		
		self.rijndaelEncrypt(rijndaelInput, temp)

		for i in range(0, 6):
			in1[i] = self.SQN[i]
			in1[i+8] = self.SQN[i]

		for i in range(0, 2):
			in1[i+6] = self.AMF[i]
			in1[i+14] = self.AMF[i]

		# XOR OPc and in1, rotate by r1=64, and XOR
		# on the constant c1 (which is all zeroes)
		for i in range(0, 16):
			rijndaelInput[(i+8) % 16] = in1[i] ^ self.OPc[i]
		rijndaelInput[15] ^= self.C[0];
		
		# XOR on the value temp computed before
		for i in range(0, 16):
			rijndaelInput[i] ^= temp[i]
		
		self.rijndaelEncrypt(rijndaelInput, out1)
		
		for i in range(0, 16):
			out1[i] ^= self.OPc[i]
		
		for i in range(0, 8):
			mac_a[i] = out1[i]

		return mac_a

	# Computes resynch authentication code MAC-S from key K, random
	# challenge RAND, sequence number SQN and authentication management
	# field AMF.
	def f1star(self):
		temp = [0]*16
		rijndaelInput = [0]*16
		in1 = [0]*16
		out1 = [0]*16
		mac_s = [0]*8	

		self.rijndaelKeySchedule(self.KI)

		# Here compute OPc if OP is given

		for i in range(0, 16):
			rijndaelInput[i] = self.RAND[i] ^ self.OPc[i]
		
		self.rijndaelEncrypt(rijndaelInput, temp)
		
		for i in range(0, 6):
			in1[i] = self.SQN[i]
			in1[i+8] = self.SQN[i]
		
		for i in range(0, 2):
			in1[i+6] = self.AMF[i]
			in1[i+14] = self.AMF[i]

		# XOR OPc and in1, rotate by r1=64, and XOR
		# on the constant c1 (which is all zeroes)		
		for i in range(0, 16):
			rijndaelInput[(i+8) % 16] = in1[i] ^ self.OPc[i]
		rijndaelInput[15] ^= self.C[0];
		
		# XOR on the value temp computed before
		for i in range(0, 16):
			rijndaelInput[i] ^= temp[i]
		
		self.rijndaelEncrypt(rijndaelInput, out1)
		
		for i in range(0, 16):
			out1[i] ^= self.OPc[i]
		
		for i in range(0, 8):
			mac_s[i] = out1[i+8]

		return mac_s

	# Takes key Ki and random challenge RAND, and 
	# returns response RES, confidentiality key CK, 
	# integrity key IK and anonymity key AK.
	def f2345(self):
		temp = [0]*16
		out = [0]*16
		rijndaelInput = [0]*16

		self.rijndaelKeySchedule(self.KI)
		
		# Here compute OPc if OP is given

		for i in range(0, 16):
			rijndaelInput[i] = self.RAND[i] ^ self.OPc[i]
		
		self.rijndaelEncrypt(rijndaelInput, temp)
		
		# To obtain output block OUT2: XOR OPc and TEMP,
		# rotate by r2=0, and XOR on the constant c2 (which
		# is all zeroes except that the last bit is 1).
		for i in range(0, 16):
			rijndaelInput[i] = temp[i] ^ self.OPc[i]
		rijndaelInput[15] ^= self.C[1]
		
		self.rijndaelEncrypt(rijndaelInput, out)
		for i in range(0, 16):
			out[i] ^= self.OPc[i]
		
		for i in range(0, 8):
			self.RES[i] = out[i+8]
		
		for i in range(0, 6):
			self.AK[i] = out[i]
		
		# To obtain output block OUT3: XOR OPc and TEMP,
		# rotate by r3=32, and XOR on the constant c3 (which
		# is all zeroes except that the next to last bit is 1).
		for i in range(0, 16):
			rijndaelInput[(i+12) % 16] = temp[i] ^ self.OPc[i]
		rijndaelInput[15] ^= self.C[2]
		
		self.rijndaelEncrypt(rijndaelInput, out)
		
		for i in range(0, 16):
			out[i] ^= self.OPc[i]
		for i in range(0, 16):
			self.CK[i] = out[i]

		# To obtain output block OUT4: XOR OPc and TEMP,
		# rotate by r4=64, and XOR on the constant c4 (which
		# is all zeroes except that the 2nd from last bit is 1). */		
		for i in range(0, 16):
			rijndaelInput[(i+8) % 16] = temp[i] ^ self.OPc[i]
		rijndaelInput[15] ^= self.C[3]
		
		self.rijndaelEncrypt(rijndaelInput, out);
		
		for i in range(0, 16):
			out[i] ^= self.OPc[i]
		
		for i in range(0, 16):
			self.IK[i] = out[i]

	# Takes key K and random challenge RAND, and 
	# returns resynch anonymity key AK.
	def f5star(self):
		temp = [0]*16
		out = [0]*16
		rijndaelInput = [0]*16

		self.rijndaelKeySchedule(self.KI);

		# Here compute OPc if OP is given

		for i in range(0, 16):
			rijndaelInput[i] = self.RAND[i] ^ self.OPc[i]
		
		self.rijndaelEncrypt(rijndaelInput, temp)
		
		# To obtain output block OUT5: XOR OPc and TEMP,
		# rotate by r5=96, and XOR on the constant c5 (which
		# is all zeroes except that the 3rd from last bit is 1).
		for i in range(0, 16):
			rijndaelInput[(i+4) % 16] = temp[i] ^ self.OPc[i]
		rijndaelInput[15] ^= self.C[4]
		
		self.rijndaelEncrypt(rijndaelInput, out);
		
		for i in range(0, 16):
			out[i] ^= self.OPc[i]
		
		for i in range(0, 6):
			self.AK[i] = out[i]

if __name__ == "__main__":
	RAND = stringToByte(a2b_hex("00000000000000000000000000000000"))
	OPc = stringToByte(a2b_hex("3CE72BE7C01A305AE798B6C96C7506F3"))
	AMF = stringToByte(a2b_hex("8000"))
	SQN = stringToByte(a2b_hex("000000000000"))
	KI = stringToByte(a2b_hex("73C0987F885595CDC2733F5B98DF6F6A"))
	
	m = Milenage(KI, RAND, OPc, SQN, AMF)	
	
	print m.f1()
	print m.f1star()
	m.f2345()
	m.f5star()
