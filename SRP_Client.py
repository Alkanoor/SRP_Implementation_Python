#!/usr/bin/python

import binascii
import hashlib
import random
import socket


server_port = 3334
server_name = 'localhost'
LEN = 1024


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((server_name, server_port))


def H(s):
    return int(hashlib.sha1(s).hexdigest(), 16)

def cryptrand(n=1024):
    return random.SystemRandom().getrandbits(n) % N


password = "5up3rs3cur3p455w0rd"
username = "Alice"


N_g_k = sock.recv(LEN)
tmp = N_g_k.split(';')
N = int(tmp[0])
g = int(tmp[1])
k = int(tmp[2])

print("N, g, k : %d %d %d" % (N,g,k))


a = cryptrand()
A = pow(g, a, N)

print("A, username (in hex) : %d %s" % (A,binascii.hexlify(username)))
sock.send(binascii.hexlify(username)+";"+str(A))

s_B = sock.recv(LEN)

if s_B == 'No user found':
	print("User %s doesn't exist in server database" %username)
	exit()
elif s_B == 'An error occured during user registration : password verifier didn\'t match':
	print("Internal server error, please contact the admin")
	exit()

tmp = s_B.split(';')
s = tmp[0]
B = int(tmp[1])

print('Received s = %s and B = %d' % (s,B))

x = H(s+username+":"+password)


u = H(str(A)+str(B))

if B%N == 0 or u%N == 0:
	print("B or u are not good for following auth operations, abortion")
	exit()

S = pow(B - k * pow(g, x, N), a + u * x, N)
K = H(str(S))

print('secret key : %d' %K)

M = H(str(H(str(N)) ^ H(str(g)))+str(H(username))+str(s)+str(A)+str(B)+str(K))
buf = sock.send(str(M))
buf = sock.recv(LEN).split('\n')

if buf[0] == "Your proof doesn't correspond to what was expected":
	print("Bad password, server aborted authentification")
	exit()

M_computed = H(str(A)+str(M)+str(K))
if M_computed != int(buf[0]):
	print("The proof sent by server is wrong : client abort following operations")
	exit()
else:
	if len(buf[1])>0:
		print(buf[1])
	else:
		print(sock.recv(LEN))
	print("Operations would continue on a real life client")