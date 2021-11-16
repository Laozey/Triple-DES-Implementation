from Cryptodome.Util.number import getPrime, inverse

key_size = 1024


def gen_keypair(k_size):
    p = getPrime(k_size//2)
    q = getPrime(k_size//2)
    assert(p != q)
    n = p * q
    e = 65537
    d = inverse(e, (p-1) * (q-1))

    return ((e, n), (d, n))


def rsa(m, k):
    return pow(m, k[0], k[1])


def rsa_enc(m, k):
    cyph = int.from_bytes(m.encode('utf-8'), 'big')
    return rsa(cyph, k)


def rsa_dec(c, k):
    msg = rsa(c, k)
    return msg.to_bytes((msg.bit_length() + 7) // 8, 'big').decode('utf-8')
