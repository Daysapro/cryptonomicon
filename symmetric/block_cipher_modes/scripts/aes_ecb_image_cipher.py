'''
Implementación de un sistema AES con el modo de operación de cifrado de bloques ECB para ver la debilidad de encriptación del modo.

Autor: Daysapro.
'''


from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from os import urandom
from hashlib import sha1
from PIL import Image


image = Image.open("../images/cryptonomicon.png")
image_data = image.convert("RGB").tobytes()

key = urandom(16)
hash = sha1()
hash.update(str(key).encode('ascii'))
key = hash.digest()[:16]
cipher = AES.new(key, AES.MODE_ECB)

ciphertext = cipher.encrypt(pad(image_data, 16))

image2 = Image.new(image.mode, image.size)
r, g, b = tuple(map(lambda d: [ciphertext[:len(image_data)][i] for i in range(0,len(ciphertext[:len(image_data)])) if i % 3 == d], [0, 1, 2])) 
image2_data = tuple(zip(r,g,b))
image2.putdata(image2_data)

image2.save("../images/aes_ecb_cryptonomicon.png", "png")