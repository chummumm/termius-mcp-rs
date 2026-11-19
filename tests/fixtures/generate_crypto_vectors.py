"""Regenerate synthetic interoperability fixtures (development only).
Requires Python cryptography and system libsodium. No Termius account is used.
The SRP formulas follow the uploaded 3.2.0 source's Botan wire contract.
"""
import base64
import ctypes
import ctypes.util
import hashlib
import hmac
import json
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

sodium = ctypes.CDLL(ctypes.util.find_library('sodium'))
sodium.sodium_init()
sodium.crypto_pwhash.argtypes = [ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_char_p,
    ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_size_t, ctypes.c_int]
sodium.crypto_secretbox_easy.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_char_p]
sodium.crypto_box_easy.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
sodium.crypto_scalarmult_base.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
def b64(x): return base64.b64encode(x).decode()
def kdf(password, salt):
    out = ctypes.create_string_buffer(32)
    assert sodium.crypto_pwhash(out, 32, password, len(password), salt, 2, 67108864, 2) == 0
    return out.raw

def secretbox(key, nonce, data):
    out = ctypes.create_string_buffer(len(data) + 16)
    assert sodium.crypto_secretbox_easy(out, data, len(data), nonce, key) == 0
    return b'\x04\x01' + nonce + out.raw

def pk(private):
    out = ctypes.create_string_buffer(32)
    assert sodium.crypto_scalarmult_base(out, private) == 0
    return out.raw

def box(public, private, nonce, data):
    out = ctypes.create_string_buffer(len(data) + 16)
    assert sodium.crypto_box_easy(out, data, len(data), nonce, public, private) == 0
    return b'\x04\x02' + nonce + out.raw

salt = bytes(range(16))
key = bytes(range(32))
nonce = bytes(range(24))
private = bytes(range(32,64))
public = pk(bytes(range(64,96)))
plaintext = 'synthetic reference: Rust / libsodium'

rn_password = b'synthetic-vault-password'
salt_enc, salt_mac, iv = salt[:8], salt[8:], bytes(range(16))
ek = hashlib.pbkdf2_hmac('sha1',rn_password,salt_enc,10000,32)
mk = hashlib.pbkdf2_hmac('sha1',rn_password,salt_mac,10000,32)
padder = padding.PKCS7(128).padder()
padded = padder.update(plaintext.encode()) + padder.finalize()
enc = Cipher(algorithms.AES(ek),modes.CBC(iv)).encryptor()
rn = b'\x03\x01' + salt_enc + salt_mac + iv + enc.update(padded) + enc.finalize()
rn += hmac.new(mk,rn,'sha256').digest()

root = Path(__file__).resolve().parents[2]
N = int((root/'src/srp_group.hex').read_text().strip(),16)
g = 19
H = lambda *xs: hashlib.blake2b(b''.join(xs),digest_size=64).digest()
minimal = lambda n: n.to_bytes(max(1,(n.bit_length()+7)//8),'big')
pad = lambda n: n.to_bytes(1024,'big')
wire = lambda n: minimal(n).hex().upper()
identifier='11111111-1111-1111-1111-111111111111'
password='synthetic-srp-password'
exponent=bytes(range(64))
a=int.from_bytes(exponent,'big')%(N-1)+1
A=pow(g,a,N)
P=base64.b64encode(kdf(password.encode(),salt))
x=int.from_bytes(H(salt,H(identifier.encode(),b':',P)),'big')
k=int.from_bytes(H(pad(N),pad(g)),'big')
v=pow(g,x,N)
b=int.from_bytes(bytes(range(64,128)),'big')
B=(k*v+pow(g,b,N))%N
u=int.from_bytes(H(pad(A),pad(B)),'big')
S=pow((B-k*v)%N,a+u*x,N)
assert S==pow((A*pow(v,u,N))%N,b,N)
K=pad(S)
xor=bytes(a^b for a,b in zip(H(minimal(N)),H(minimal(g))))
M=H(xor,H(identifier.encode()),salt,minimal(A),minimal(B),H(K))
M2=H(minimal(A),minimal(int.from_bytes(M,'big')),H(K))
session_salt=bytes([33])*16
wrapped=secretbox(kdf(base64.b64encode(K),session_salt),nonce,b'fixture-device-token')

vectors={
  'provenance': 'Synthetic known-answer data: system libsodium crypto_pwhash/secretbox/box; Python cryptography RNCryptor; independent Python SRP client/server agreement.',
  'argon2':{'password':password,'salt':b64(salt),'key':b64(kdf(password.encode(),salt))},
  'secretbox':{'key':b64(key),'ciphertext':b64(secretbox(key,nonce,plaintext.encode())),'plaintext':plaintext},
  'box':{'public_key':b64(public),'private_key':b64(private),'ciphertext':b64(box(public,private,nonce,key)),'plaintext':b64(key)},
  'entity':{'key':b64(key),'ciphertext':b64(secretbox(key,nonce,json.dumps({'id':999,'label':'fixture shared host','address':'192.0.2.10','ssh_config':7}).encode()))},
  'rncryptor':{'password':rn_password.decode(),'salt':b64(salt_enc),'hmac_salt':b64(salt_mac),'ciphertext':b64(rn),'plaintext':plaintext},
  'srp':{'identifier':identifier,'password':password,'salt':b64(salt),'exponent':b64(exponent),
    'server_public':wire(B),'client_public':wire(A),'client_proof':wire(int.from_bytes(M,'big')),
    'server_proof':wire(int.from_bytes(M2,'big')),'session_salt':b64(session_salt),'wrapped_token':b64(wrapped)}
}
Path(__file__).with_name('crypto_vectors.json').write_text(json.dumps(vectors,indent=2)+'\n')
print('Wrote synthetic cryptographic interoperability fixtures.')
