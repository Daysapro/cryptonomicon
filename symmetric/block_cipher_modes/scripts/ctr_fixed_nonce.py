'''
Implementación de un ataque estadístico a un nonce reutilizado en el modo CTR.
 
Este script utiliza una puntuación para cada carácter en inglés. Esta puntuación puede no ser aplicable a todos los casos.
 
Ni en este caso ideal se consigue el resultado exacto, ya que la frecuencia de las letras es una mera media aritmética, sin considerar que ciertas letras son más probables al principio de palabras muy comunes u otras circunstancias que dificultan la tarea.
 
Autor: Daysapro.
'''
 
 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from os import urandom
from hashlib import sha1
 
 
BLOCK_SIZE = 16
key = urandom(BLOCK_SIZE)
nonce = urandom(BLOCK_SIZE - 1)
secret = b"flag{fixed_nonce}"
 
def aes_ctr_encrypt(key, input, nonce):
    hash = sha1()
    hash.update(str(key).encode('ascii'))
    key = hash.digest()[:BLOCK_SIZE]
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.encrypt(pad(input, BLOCK_SIZE))
 
messages = [b"a house near the mountains. I have two brothers", b"and one sister, and I was born", b"last. My father teaches mathematics, and", b"is a nurse at a big hospital My brothers are", b"very smart and work hard in school", b"but she is very kind. My grandmother", b"grandmother also lives with us. She came from Italy", b"when I was two years old She has grown old", b"but she is still very strong She cooks the best food", b"My brothers and I like to go on long walks in the mountains", b"has grown old, but she is still very strong", b"On the weekends we all play board games together", b"We laugh and always have a good time"]
ciphertexts = []
 
for message in messages:
    ciphertexts.append(aes_ctr_encrypt(key, message, nonce))
 
ciphertexts.append(aes_ctr_encrypt(key, secret, nonce))
 
print("Textos cifrados:")
for ciphertext in ciphertexts:
    print(ciphertext)
 
 
length = 1000
for ciphertext in ciphertexts:
    if length > len(ciphertext):
        length = len(ciphertext)
 
letters_sets = []
for i in range(length):
    letters_set = []
    for ciphertext in ciphertexts:
        letters_set.append(ciphertext[i])
    letters_sets.append(letters_set)
 
frequencies = {
    ' ': 700000000,
    'e': 390395169,
    't': 282039486,
    'a': 248362256,
    'o': 235661502,
    'i': 214822972,
    'n': 214319386,
    's': 196844692,
    'h': 193607737,
    'r': 184990759,
    'd': 134044565,
    'l': 125951672,
    'u': 88219598,
    'c': 79962026,
    'm': 79502870,
    'f': 72967175,
    'w': 69069021,
    'g': 61549736,
    'y': 59010696,
    'p': 55746578,
    'b': 47673928,
    'v': 30476191,
    'k': 22969448,
    'x': 5574077,
    'j': 4507165,
    'q': 3649838,
    'z': 2456495
}
 
keystream = ""
for letters_set in letters_sets:
    best_key = 0
    best_score = 0
    for byte in range(256):
        letters = [chr(character ^ byte) for character in letters_set]
        score = 0
        for character in letters:
            if character.lower() in frequencies:
                score += frequencies[character.lower()]
        if score > best_score:
            best_key = byte
            best_score = score
    keystream += chr(best_key)
 
messages = []
for ciphertext in ciphertexts:
    message = ""
    counter = 0
    for character in ciphertext[:len(keystream)]:
        message += chr(ord(keystream[counter]) ^ character)
        counter += 1
    messages.append(message)
 
print("\nTextos recuperados:")
for message in messages:
    print(message)