import hashlib
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA 
from Crypto.Signature import PKCS1_v1_5 
import base64
import os
import argparse
import re
import subprocess
key = RSA.generate(2048, e=65537)
pub = key.publickey()
priv = key.exportKey('PEM')
block_size = 65535
hasher = hashlib.sha256()
with open("2048", "rb") as g:
	buf = g.read(block_size)
	while len(buf) > 0:	
		hasher.update(buf)
		buf = g.read(block_size)
with open("2048_hash.txt", "w") as h:
	h.write(hasher.hexdigest())

try:
	f_out = open("2048_sig.txt", "w")
except Exception as e:
	print("Error, could not open game output file: %s" % (e))
	f.close()
	exit(1)

signer = PKCS1_v1_5.new(priv)
with open("2048_hash.txt", "rb") as s:
	buf_s = s.read()
	print(buf_s)
	digest = SHA256.new()
	digest.update(buf_s)
	signature = signer.sign(digest)
	f_out.write(signature)

	


