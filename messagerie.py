import rsa
import tdes

def enc_tdes_keys(keys, pub_key):
    enc_keys = []
    for key in keys:
        enc_keys.append(rsa.rsa_enc(key, pub_key))

    return enc_keys

def dec_tdes_keys(enc_keys, priv_key):
    dec_keys = []
    for enc_key in enc_keys:
        dec_keys.append(rsa.rsa_dec(enc_key, priv_key))

    return dec_keys

def prg():
    rsa_keys = []
    rsa_keys.append(rsa.gen_keypair(rsa.key_size))
    rsa_keys.append(rsa.gen_keypair(rsa.key_size))

    tdes_keys = []
    tdes_keys.append(tdes.gen_keys())
    tdes_keys.append(tdes.gen_keys())

    names = []
    names.append(input("Enter user A's name: "))
    names.append(input("Enter user B's name: "))

    while 1:
        for i in range(2):
            msg = input("\n> ")

            if (len(msg) == 0):
                return

            cypher, keys = tdes.tdes_enc(msg, tdes_keys[i]), enc_tdes_keys(tdes_keys[i], rsa_keys[(i + 1) % 2][0])

            # Passage à l'autre utilisateur
            dec_msg = tdes.tdes_dec(cypher, dec_tdes_keys(keys, rsa_keys[(i + 1) % 2][1]))

            print(names[i] + ": " + dec_msg)

prg()
