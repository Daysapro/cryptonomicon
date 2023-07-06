from Crypto.PublicKey import RSA
from Crypto.Util.number import GCD
from Crypto.Util.number import isPrime, long_to_bytes


with open("public.pem", "r") as archivo:
    pem = archivo.read()

public_key = RSA.importKey(pem)

n = public_key.n
e = public_key.e

it = 8
bits = 512

seed = 211286818345627549183608678726370412218029639873054513839005340650674982169404937862395980568550063504804783328450267566224937880641772833325018028629959635
s1 = 2166771675595184069339107365908377157701164485820981409993925279512199123418374034275465590004848135946671454084220731645099286746251308323653144363063385
s2 = 6729272950467625456298454678219613090467254824679318993052294587570153424935267364971827277137521929202783621553421958533761123653824135472378133765236115
s3 = 2230396903302352921484704122705539403201050490164649102182798059926343096511158288867301614648471516723052092761312105117735046752506523136197227936190287
s4 = 4578847787736143756850823407168519112175260092601476810539830792656568747136604250146858111418705054138266193348169239751046779010474924367072989895377792
s5 = 7578332979479086546637469036948482551151240099803812235949997147892871097982293017256475189504447955147399405791875395450814297264039908361472603256921612
s6 = 2550420443270381003007873520763042837493244197616666667768397146110589301602119884836605418664463550865399026934848289084292975494312467018767881691302197

t0 = s1 - seed
t1 = s2 - s1
t2 = s3 - s2
t3 = s4 - s3
t4 = s5 - s4
t5 = s6 - s5

multiple1 = (t0 * t2) - pow(t1, 2)
multiple2 = (t1 * t3) - pow(t2, 2)
multiple3 = (t2 * t4) - pow(t3, 2)
multiple4 = (t3 * t5) - pow(t4, 2)
multiple5 = (t3 * t0) - (t1 * t2)
multiple6 = (t4 * t0) - (t1 * t3)
multiple7 = (t5 * t0) - (t1 * t4)
multiple8 = (t4 * t1) - (t2 * t3)
multiple9 = (t5 * t1) - (t2 * t4)
multiple10 = (t5 * t2) - (t3 * t4)

n2 = GCD(multiple1, multiple2, multiple3, multiple4, multiple5, multiple6, multiple7, multiple8, multiple9, multiple10)

m = (s2 - s1) * pow(s1 - seed, -1, n2) % n2

c = s1 - seed*m % n2

assert s1 == (seed * m + c) % n2


class LCG:
    lcg_m = m
    lcg_c = c
    lcg_n = n2

    def __init__(self, lcg_s):
        self.state = lcg_s

    def next(self):
        self.state = (self.state * self.lcg_m + self.lcg_c) % self.lcg_n
        return self.state


lcg = LCG(seed)

primes_arr = []
primes_n = 1
while True:
    for i in range(it):
        while True:
            prime_candidate = lcg.next()
            if not isPrime(prime_candidate):
                continue
            elif prime_candidate.bit_length() != bits:
                continue
            else:
                primes_n *= prime_candidate
                primes_arr.append(prime_candidate)
                break
    if primes_n.bit_length() > 4096:
        print("bit length", primes_n.bit_length())
        primes_arr.clear()
        primes_n = 1
        continue
    else:
        break

phi = 1
for k in primes_arr:
    phi *= (k - 1)

t3 = pow(e, -1, phi)

with open("flag.txt", "rb") as flag_file:
    flag = flag_file.read()

ciphertext = int.from_bytes(flag, "little")

flag = pow(ciphertext, t3, n)

print(long_to_bytes(flag))