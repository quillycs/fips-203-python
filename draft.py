import hashlib

q = 3329

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