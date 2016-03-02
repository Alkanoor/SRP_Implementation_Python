#!/usr/bin/python

import binascii
import hashlib
import random


password = "5up3rs3cur3p455w0rd"

possibleUsers = {}
#Des entites utilisateur (identifiant,sel,v=g^(H(s,p))) ont ete generees et placees dans un fichier users.txt
with open("users.txt","r") as f:
	content = f.read().split('\n')
	for key in content:
		tmp = key.split('=')
		if len(tmp)>1:
			user = binascii.unhexlify(tmp[0])
			possibleUsers.update({user:[]})
			tmp = tmp[1].split('::')
			for i in range(len(tmp)):
				tmp2 = tmp[i].split(';')
				if len(tmp2)>1:
					possibleUsers[user].append((binascii.unhexlify(tmp2[0]),int(tmp2[1])))

print possibleUsers

possibleN = []
#Des entiers premiers safe N (4) ont ete generes en utilisant la commande "openssl dhparam -text 1024" et places dans un fichier possibleN.txt
with open("possibleN.txt","r") as f:
	content = f.read().split('\n\n')
	for key in content:
		possibleN.append(int(key.replace('\n','').replace(':',''),16))

g = 2


def authenticate(connection):
	def H(s):
	    return int(hashlib.sha1(s).hexdigest(), 16)

	def cryptrand(n=1024):
	    return random.SystemRandom().getrandbits(n) % N

	indexN = random.randint(0,len(possibleN)-1)	
	N = possibleN[indexN]
	k = H(str(N)+str(g))
	connection.sendall((str(N)+";"+str(g)+";"+str(k)+";").encode('ascii'))

	Id_A = connection.recv(LEN).split(";")
	id = binascii.unhexlify(Id_A[0])
	A = int(Id_A[1])

	if A%N == 0:
		return (False, "A doesn't fullfill conditions for following operations")
	
	entity = -1
	for user in possibleUsers:
		if user==id:
			entity = possibleUsers[user][indexN]

	if entity==-1:
		return (False, "No user found")

	user = id
	salt = entity[0]
	v = entity[1]
	x = H(salt+user+":"+password)
	if v!=pow(g, x, N):
		return (False, "An error occured during user registration : password verifier didn't match")

	b = cryptrand()
	B = (k * v + pow(g, b, N)) % N
	connection.sendall(salt+";"+str(B))

	u = H(str(A)+str(B))

	S = pow(A * pow(v, u, N), b, N)
	K = H(str(S))

	print('secret key : %d'%K)
	
	#then we check if secret keys are same in both client and server (with hashes)
	M_computed = H(str(H(str(N)) ^ H(str(g)))+str(H(user))+str(salt)+str(A)+str(B)+str(K))
	
	M_fromUser = connection.recv(LEN)
	if M_computed != int(M_fromUser):
		return (False, "Your proof doesn't correspond to what was expected")

	M_toUser = H(str(A)+M_fromUser+str(K))
	connection.sendall(str(M_toUser)+'\n')	

	return (True, "Congratz, you're now identified")



import socket
import sys

LEN = 4096

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

if len(sys.argv)>1:
	server_name = sys.argv[1]
else:
	server_name = "localhost"

server_port = 3334
server_address = (server_name, server_port)
print >>sys.stderr, 'starting up on %s server_port %s' % server_address
sock.bind(server_address)
sock.listen(1)

while True:
    print >>sys.stderr, 'waiting for a connection'
    connection, client_address = sock.accept()
    try:
        print >>sys.stderr, 'client connected:', client_address
        result = authenticate(connection)
	if result[0]:
	    print >>sys.stderr, 'Auth Success : "%s"' % result[1]
        else:
	    print >>sys.stderr, 'Auth failed : "%s"' % result[1]
        try:
		connection.sendall(result[1])
	except:
		print >>sys.stderr, 'Connexion aborted by client'
    finally:
        connection.close()