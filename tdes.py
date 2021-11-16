import random
import math

import tables

# Fonction utiles

# Prend un entier et retourne sa version binaire en chaîne de charactères
def fmt_bin(n, len):
    return format(n, "0" + str(len) + "b")

# Prends un chaîne de charactères et retourne sa version binaire en chaîne de charactères
def to_binary(s):
    b = ""
    for c in s:
        b += fmt_bin(ord(c), 8)
    return b

# Inverse de to_binary
def to_string(b):
    s = ""
    offset = 0
    while offset < len(b):
        s += chr(int(b[offset:offset+8], 2))
        offset += 8
    return s

# Retourne la valeur maximale possible sur n bits
def n_bits_max_value(bits_count):
    return math.floor(math.pow(2, bits_count) - 1)

# Prend une liste de n bits et retourne sa partie droite et gauche
def split_n_bits(b, n):
    b = int(b, 2)
    splited_bits = math.floor(n/2)
    c0 = fmt_bin(b >> splited_bits, splited_bits)
    d0 = fmt_bin(b & n_bits_max_value(splited_bits), splited_bits)
    return c0, d0


def create_block(prev_subkey, subkey_len, shift_count):
    pc, pd = prev_subkey
    nc = pc[shift_count:subkey_len] + pc[0:shift_count]
    nd = pd[shift_count:subkey_len] + pd[0:shift_count]
    return nc, nd

# Concatène les 2 éléments ensemble (Utiliser dans concat subkey_parts)
def concat(ps):
    return ps[0] + ps[1]

# Assemble les chaque sous-clefs des clefs de tour
def concat_subkey_parts(subkeys):
    return [concat(sp) for sp in subkeys]


def expand(rp):
    return permute_bits(rp, tables.bst)


def get_6_bits_groups(xerp):
    start = 0
    end = 6
    bgroups = []
    for _ in range(8):
        bgroups.append(xerp[start:end])
        start = end
        end += 6
    return bgroups


def pass_in_sbox(bgroup, sbox):
    i = int(bgroup[0:1] + bgroup[5:6], 2)
    j = int(bgroup[1:5], 2)
    return fmt_bin(sbox[i][j], 4)


def reverse(subpm):
    return subpm[1] + subpm[0]


def gen_64_bits():
    return fmt_bin(random.getrandbits(64), 64)


def permute_bits(bits, pt):
    pb = ""
    for i in range(len(pt)):
        pb = pb + bits[pt[i]-1]
    return pb


def permute_subkeys(subkeys):
    return [permute_bits(subkey, tables.pc2) for subkey in subkeys]


def split_in_64bits_groups(elements):
    split = 0
    output = []
    while split < len(elements):
        grp = elements[split:split+64]
        if len(grp) < 64:
            grp = grp.rjust(64, "0")
        output.append(grp)
        split += 64

    return output


def get_subkey(key):
    pkl = permute_bits(key, tables.pc1)
    subkey0 = split_n_bits(pkl, 56)
    subkeys = [create_block(subkey0, 28, tables.left_shifts[0])]
    for i in range(1, 16):
        subkeys.append(create_block(subkeys[i-1], 28, tables.left_shifts[i]))

    csubkeys = concat_subkey_parts(subkeys)

    return permute_subkeys(csubkeys)


def f(rp, k):
    erp = expand(rp)
    xerp = fmt_bin(int(k, 2) ^ int(erp, 2), 48)
    bgroups = get_6_bits_groups(xerp)
    sbgroups = ""
    for i in range(8):
        sbgroups += pass_in_sbox(bgroups[i], tables.sboxs[i])
    return permute_bits(sbgroups, tables.p)


def rounds(subpm, subkeys, i):
    l = subpm[1]
    r = int(subpm[0], 2) ^ int(f(subpm[1], subkeys[i]), 2)
    subpm = [l, fmt_bin(r, 32)]
    if i == 15:
        return subpm
    return rounds(subpm, subkeys, i+1)


def back_rounds(subpm, subkeys, i):
    l = subpm[1]
    r = int(subpm[0], 2) ^ int(f(subpm[1], subkeys[len(subkeys) - (i + 1)]), 2)
    subpm = [l, fmt_bin(r, 32)]
    if i == 15:
        return subpm
    return back_rounds(subpm, subkeys, i+1)


def des_enc(m, k):
    subkeys = get_subkey(k)
    pm = permute_bits(m, tables.ip)
    subpm0 = split_n_bits(pm, 64)
    subpm16 = rounds(subpm0, subkeys, 0)
    rsubpm16 = reverse(subpm16)
    return permute_bits(rsubpm16, tables.fp)


def des_dec(c, k):
    subkeys = get_subkey(k)
    pc = permute_bits(c, tables.ip)
    subpc0 = split_n_bits(pc, 64)
    subpc16 = back_rounds(subpc0, subkeys, 0)
    rsubpc16 = reverse(subpc16)
    return permute_bits(rsubpc16, tables.fp)


def des_enc_msg(msg, k):
    blocks = split_in_64bits_groups(msg)

    cypher = ""
    for block in blocks:
        cypher += des_enc(block, k)

    return cypher


def des_dec_msg(cyph, k):
    blocks = split_in_64bits_groups(cyph)

    msg = ""
    for block in blocks:
        msg += des_dec(block, k)

    return msg


def tdes_enc(m, keys):
    fmt_m = to_binary(m)
    return des_enc_msg(des_dec_msg(des_enc_msg(fmt_m, keys[0]), keys[1]), keys[2])


def tdes_dec(c, keys):
    dm = des_dec_msg(des_enc_msg(des_dec_msg(c, keys[2]), keys[1]), keys[0])
    return to_string(dm)


def gen_keys():
    keys = []
    for _ in range(3):
        keys.append(gen_64_bits())
    assert(keys[0] != keys [1] != keys[2])
    return keys
