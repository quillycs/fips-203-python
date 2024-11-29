import hashlib

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

    for length in range(128, 1, -1 // 2):
        for start in range(0, 256, 2 * length):
            omega = pow(zeta, BitRev7(i), q)
            i += 1

            for j in range(start, start + length):
                t = omega * f_hat[j + length] % q
                f_hat[j + length] = (f_hat[j] - t) % q 
                f_hat[j] = (f_hat[j] + t) % q

    return f_hat