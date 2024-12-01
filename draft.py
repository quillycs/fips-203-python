import hashlib
import random
import os

q = 3329
zeta = 17

def xof_init():
    return hashlib.shake_128()

def xof_absorb(ctx, str):
    ctx.update(str)
    return ctx

def xof_squeeze(ctx, z):
    output = ctx.digest(z)

    return ctx, output

def G(c):
    hash_output = hashlib.sha3_512(c).digest()

    a = hash_output[:32]
    b = hash_output[32:]

    return a, b

def BytesToBits(B):
    b = []

    C = list(B)

    for i in range(len(C)):
        for j in range(8):
            b.append(C[i] % 2)
            C[i] //= 2

    return b

def SamplePolyCBD(B, eta):
    b = BytesToBits(B)
    f = [0] * 256

    for i in range(256):
        x = sum(b[2 * i * eta + j] for j in range(eta))
        y = sum(b[2 * i * eta + eta + j] for j in range(eta))
        f[i] = (x - y) % q

    return f

def BitRev7(r):
    return int('{:07b}'.format(r)[::-1], 2)

def NTT(f):
    f_hat = f[:]
    i = 1

    length = 128

    while length >= 2:
        for start in range(0, 256, 2 * length):
            omega = pow(zeta, BitRev7(i), q)
            i += 1

            for j in range(start, start + length):
                t = omega * f_hat[j + length] % q
                f_hat[j + length] = (f_hat[j] - t) % q 
                f_hat[j] = (f_hat[j] + t) % q

        length //= 2

    return f_hat

def BitsToBytes(b):
    B = [0] * (len(b) // 8)

    for i in range(len(b)):
        B[i // 8] += b[i] * (2 ** (i % 8))

    return B

def ByteEncode(F, d):
    b = []

    for i in range(256):
        a = F[i]

        for j in range(d):
            b.append(a % 2)
            a = (a - b[i * d + j]) // 2

    B = BitsToBytes(b)
    return bytes(B)

def PRF(eta, s, b):
    input_data = s + bytes([b])
    shake = hashlib.shake_256(input_data)
    output = shake.digest(64 * eta)
    return output

def SampleNTT(B):
    ctx = xof_init()
    ctx = xof_absorb(ctx, B)
    j = 0
    a_hat = [0] * 256

    while j < 256:
        ctx, C = xof_squeeze(ctx, 3)
        d1 = C[0] + 256 * (C[1] % 16)
        d2 = (C[1] // 16) + 16 * C[2]

        if d1 < q:
            a_hat[j] = d1
            j += 1

        if d2 < q and j < 256:
            a_hat[j] = d2
            j += 1

    return a_hat

def kpkekeygen(d, k):
    rho, sigma = G(d + bytes([k]))
    N = 0

    A = []

    for i in range(k):
        row = []

        for j in range(k):
            B = rho + bytes([j, i])
            row.append(SampleNTT(B))

        A.append(row)

    s = []

    for i in range(k):
        prf_output = PRF(2, sigma, N)
        s.append(SamplePolyCBD(prf_output, 2))
        N += 1

    e = []

    for i in range(k):
        prf_output = PRF(2, sigma, N)
        e.append(SamplePolyCBD(prf_output, 2))
        N += 1

    s_hat = [NTT(s[i]) for s_i in s]
    e_hat = [NTT(e[i]) for e_i in e]

    t = []

    for i in range(k):
        t_row = [sum(A[i][j][n] * s_hat[j][n] % q for j in range(k)) % q for n in range(256)]
        t.append([(t_row[n] + e_hat[i][n]) % q for n in range(256)])

    ekPKE = b"".join(ByteEncode(t_i, 12) for t_i in t) + rho
    dkPKE = b"".join(ByteEncode(s_hat_i, 12) for s_hat_i in s_hat)
    
    return ekPKE, dkPKE