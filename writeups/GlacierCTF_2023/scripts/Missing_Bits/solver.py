from Crypto.Util.number import bytes_to_long, long_to_bytes
from base64 import b64decode


private_key = b"""xwiBgUBTtaSyUvdrqfgAEduRdnzRbKcwEheMxwIDAQABAoIBAAqaJbojNCwYqykz
n0Fn2sxMsho4PhThPQcX79AGqSxVNxviWK2GXETP7SsnvWGmRXHIRnR6JGOhyHVe
dTDYZxOAOhl85FksVQYVUaygf9Epekja/vSj5OE8NIcAdEBr3aZ6gdLxi+q1a5Kh
1nEmsF6FiYGpsPkN63ovbow/CKt4N7UQJqZEQw380rNA0sOQenmzXRFOpXA8PRFb
G6itGRiP1gB9tpdQnWggQ5n+x8/2k+k3CRW6/xIP9dMAVZh2jVombenLxgnhQCJB
bYaR4I8B0zzYqXqFfeHCMNl+pJmmmFcvs2ZE71fqyjRid6ZDqS4GXtSuRQM0UL7L
UQVBaYECgYEA5BiLN7FjwgOuT4FKxFdzizdq/t5mvRksbmBP/JWk3vxQYeCmMiPQ
xrQUqdHGGxG8iMIwH7dnhNaPa81lrP9fCKyij/caEbe4lmEm+VdM/xZQF+PiCc1f
ziYXphz9wuAc8++kvKxM2EaiDe8F25nsXW+FaxNoXKbJg0zTQLyzKiECgYEA8SLi
hbAwo2l0zal8GMIemzr+APxLw+fmd4aryVAMov8ANkG8KDMwdmvvkn3rL7WaKym5
fakqvXR45/QGPe8niVzx6oaWGSSfijeVan27pG/bzVqyymFHZP9cRhEHW4HN57hO
pXy0kUFqVaxJWCs+thH0LTZoToAepg+sr82FaecCgYEAnJnpQzRsHDEwxO8sqP6t
moBS2mdRPDUDV0iSwgTvrBSpD3oQQM5sMXBD24/lpoIX4gEIz025Ke+xij77trmh
wq/b8GGjqVRsy/opqvjwKRZlqPFRKI+zXjKy+95dryT1W9lFTjAxli9wZYaci/fy
2veNL0Wk2i+8nIPraj/j9mECgYEA0ou6LC7OGTDwKs7sqxV78eBNfoDMis7GPeEZ
x9ocXom3HqjA6HzhuNS/xzIpE2xGo5939c+qoOe81hMNDDDwXZEJLdS75FJE90NX
NDd6iracvi6OZAUSeI47fHZL7UtmhQg5q2c6poXumcWn+NMxm3oLsRqLcteNa0PO
bWZPMksCgYBidblknACvEinDUQB8dvElzROql0ZUMX9hQOsSrg0ju3smun8qujcT
PJQrWctoNw0ZXnQjDkVzaJxog1F3QkKUg6B1Rn2Q0RYuCAeNDn+KqBkTT18Du7yw
+GU/4U6EMw+uL7dNjasD1jjx90ro6RmDDBmGDQuludO0G7h9XQzl+Q=="""

print(hex(bytes_to_long(b64decode(private_key))))

p = 0xe4188b37b163c203ae4f814ac457738b376afede66bd192c6e604ffc95a4defc5061e0a63223d0c6b414a9d1c61b11bc88c2301fb76784d68f6bcd65acff5f08aca28ff71a11b7b8966126f9574cff165017e3e209cd5fce2617a61cfdc2e01cf3efa4bcac4cd846a20def05db99ec5d6f856b13685ca6c9834cd340bcb32a21
q = 0xf122e285b030a36974cda97c18c21e9b3afe00fc4bc3e7e67786abc9500ca2ff003641bc283330766bef927deb2fb59a2b29b97da92abd7478e7f4063def27895cf1ea869619249f8a37956a7dbba46fdbcd5ab2ca614764ff5c4611075b81cde7b84ea57cb491416a55ac49582b3eb611f42d36684e801ea60facafcd8569e7
d = 0xa9a25ba23342c18ab29339f4167dacc4cb21a383e14e13d0717efd006a92c55371be258ad865c44cfed2b27bd61a64571c846747a2463a1c8755e7530d86713803a197ce4592c55061551aca07fd1297a48dafef4a3e4e13c34870074406bdda67a81d2f18beab56b92a1d67126b05e858981a9b0f90deb7a2f6e8c3f08ab7837b51026a644430dfcd2b340d2c3907a79b35d114ea5703c3d115b1ba8ad19188fd6007db697509d68204399fec7cff693e9370915baff120ff5d3005598768d5a266de9cbc609e14022416d8691e08f01d33cd8a97a857de1c230d97ea499a698572fb36644ef57eaca346277a643a92e065ed4ae45033450becb5105416981

n = p * q
phi = (p - 1) * (q - 1)


with open("ciphertext_message", 'rb') as file:
    print(long_to_bytes(pow(bytes_to_long(file.read()), d, n)))