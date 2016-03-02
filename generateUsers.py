#!/usr/bin/python

import sys
import random
import hashlib
import binascii


possibleN = []
#Des entiers N (4) ont ete generes en utilisant la commande "openssl dhparam -text 1024" et places dans un fichier possibleN.txt
with open("possibleN.txt","r") as f:
	content = f.read().split('\n\n')
	for key in content:
		possibleN.append(int(key.replace('\n','').replace(':',''),16))

def H(s):
	return int(hashlib.sha1(s).hexdigest(), 16)

g = 2

if len(sys.argv)>1:
	userToAdd = sys.argv[1]
else:
	userToAdd = "Alice"

password = "5up3rs3cur3p455w0rd"

with open("users.txt","a") as f:
	f.write(binascii.hexlify(userToAdd)+"=")
	for n in possibleN:
		salt = random.SystemRandom().getrandbits(40)
		if len(hex(salt).replace('L',''))%2 == 1:
			finalSalt = "0"+hex(salt).replace('L','').replace('0x','')
			v = pow(g,H(binascii.unhexlify(str(finalSalt))+userToAdd+":"+password),n)
			f.write(finalSalt+";"+str(v)+"::")
		else:
			finalSalt = hex(salt).replace('L','').replace('0x','')
			v = pow(g,H(binascii.unhexlify(str(finalSalt))+userToAdd+":"+password),n)
			f.write(finalSalt+";"+str(v)+"::")
	f.write('\n')
	