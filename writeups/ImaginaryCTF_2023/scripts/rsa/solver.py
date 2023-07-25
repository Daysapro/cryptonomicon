from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes


with open("flag.enc", 'rb') as flag:
    flag_text = flag.read()
    
private_key = RSA.importKey(open("private.pem", "r").read())
public_key = RSA.importKey(open("public.pem", "r").read())

n = public_key.n
d = private_key.d

print(long_to_bytes(pow(bytes_to_long(flag_text), d, n)))