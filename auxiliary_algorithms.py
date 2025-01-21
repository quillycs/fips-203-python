# The function PRF takes a parameter 𝜂 ∈ {2, 3}, one 32-byte input, and one 1-byte input. It produces one (64 ⋅ 𝜂)-byte output.
def PRF(eta, s, b):    
    input_data = s + bytes([b])
    shake = hashlib.shake_256(input_data)
    output = shake.digest(64 * eta)
    return output

# The function G takes one variable-length input and produces two 32-byte outputs.
def G(c):
    hash_output = hashlib.sha3_512(c).digest()

    a = hash_output[:32]
    b = hash_output[32:]

    return a, b

# This standard uses a XOF wrapper defined in terms of the incremental API for SHAKE128 in SP 800-185.
# The SHAKE128 API consists of three functions.
def xof_init():
    return hashlib.shake_128()

def xof_absorb(ctx, str):
    ctx.update(str)
    return ctx

def xof_squeeze(ctx, z):
    output = ctx.digest(z)

    return ctx, output

# Converts a bit array (of a length that is a multiple of eight) into an array of bytes.
def BitsToBytes(b):
    B = [0] * (len(b) // 8)

    for i in range(len(b)):
        B[i // 8] += b[i] * (2 ** (7 - (i % 8)))

    return B

# Performs the inverse of BitsToBytes, converting a byte array into a bit array.
def BytesToBits(B):
    b = [0] * (len(B) * 8)

    for i in range(len(B)):
        for j in range(8):
            b[i * 8 + j] = (B[i] >> (7 - j)) & 1

    return b

# The Compress and Decompress algorithmssatisfy two important properties.
# First, decompression followed by compression preserves the input.
# Second, if 𝑑 is large (i.e., close to 12), compression followed by decompression does not significantly alter the value.
def compress(x, d):
    return round((2 ** d / q) * x) % (2 ** d)

def decompress(y, d):
    return round((q / (2 ** d)) * y)

# Encodes an array of 𝑑-bit integers into a byte array for 1 ≤ 𝑑 ≤ 12.
def ByteEncode(F, d):
    b = []

    for i in range(256):
        a = F[i]

        for j in range(d):
            b.append(a % 2)
            a = (a - b[i * d + j]) // 2

    B = BitsToBytes(b)
    return bytes(B)

# Decodes a byte array into an array of 𝑑-bit integers for 1 ≤ 𝑑 ≤ 12.
def ByteDecode(B, d):
    b = BytesToBits(B)
    m = 2**d if d < 12 else q
    F = [0] * 256

    for i in range(256):
        F[i] = sum(b[i * d + j] * (2**j) for j in range(d)) % m

    return F

# Takes a 32-byte seed and two indices as input and outputs a pseudorandom element of 𝑇_𝑞.
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

# Takes a seed as input and outputs a pseudorandom sample from the distribution D_𝜂(𝑅_𝑞).
def SamplePolyCBD(B, eta):
    b = BytesToBits(B)
    f = [0] * 256

    for i in range(256):
        x = sum(b[2 * i * eta + j] for j in range(eta))
        y = sum(b[2 * i * eta + eta + j] for j in range(eta))
        f[i] = (x - y) % q

    return f

# Computes the NTT representation 𝑓_hat of the given polynomial 𝑓 ∈ 𝑅_𝑞.
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

# Computes the polynomial 𝑓 ∈ 𝑅_𝑞 that corresponds to the given NTT representation 𝑓_hat ∈ 𝑇_𝑞.
def NTT_inv(f_hat):
    f = f_hat[:]
    i = 127

    length = 2

    while length <= 128:
        for start in range(0, 256, 2 * length):
            zeta = pow(17, BitRev7(i), q)
            i -= 1

            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % q
                f[j + length] = zeta * (f[j + length] - t) % q

        length *= 2

    f = [(x * 3303) % q for x in f]
    
    return f
