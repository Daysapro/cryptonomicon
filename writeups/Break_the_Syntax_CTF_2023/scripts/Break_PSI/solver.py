from Crypto.Hash import SHA256
from Crypto.Util.number import long_to_bytes
from pwn import *
from tqdm import tqdm


limit = 32
setSize = 17
reps = 8


def F(x):
    h = SHA256.new(data=long_to_bytes(x))
    return h.digest().hex()


def hash_list(l):
    h = SHA256.new(data=bytes(str(l), "utf-8"))
    return h.digest()


def intersection(A, B):
    return [v for v in A if v in B]


def is_valid(Asi, Bsi):
    if Asi == [] or Bsi == []:
        return 0
    if hash_list(Asi) != hash_list(Bsi):
        return 0

    cnt = {}
    for a in Asi:
        if a_inv[a] in cnt:
            cnt[a_inv[a]] += 1
        else:
            cnt[a_inv[a]] = 1
    for v in cnt.values():
        if v != reps + 1:
            return 0

    cnt = {}
    for b in Bsi:
        if b_inv[b] in cnt:
            cnt[b_inv[b]] += 1
        else:
            cnt[b_inv[b]] = 1
    for v in cnt.values():
        if v != reps + 1:
            return 0
    return 1


def get_hash_dict():
    hash_dict = {}
    for i in range(288):
        hash_dict[F(i)] = i
    return hash_dict


def get_values(hashes):
    values = []
    for hash in hashes:
        values.append(hash_dict[hash])
    return values


def get_inv(values):
    inv = {}
    for value in values:
        h = F(value)
        inv[h] = value % limit
    return inv

r = remote("crypto-breakpsi.ch.bts.wh.edu.pl", 1337)


for i in tqdm(range(420)):
    Alice = eval(r.recvline().strip()[7:].decode('utf-8'))
    Bob = eval(r.recvline().strip()[4:].decode('utf-8'))

    hash_dict = get_hash_dict()
    a_values = get_values(Alice)
    b_values = get_values(Bob)
    a_inv = get_inv(a_values)
    b_inv = get_inv(b_values)

    real_intersection = intersection(Alice, Bob)

    real_intersection[0] = F(hash_dict[real_intersection[0]] + limit)

    assert is_valid(real_intersection, real_intersection)

    str_intersection = ""
    for i in real_intersection:
        str_intersection += i + " "

    r.recvuntil(b": ")
    r.sendline(str_intersection)
    r.recvuntil(b": ")
    r.sendline(str_intersection)

print(r.recvall())