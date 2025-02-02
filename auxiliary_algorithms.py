from Crypto.Hash import SHAKE128
import parameter_set as params
import hashlib

TwoBitRev7_values = [
    17, -17, 2761, -2761, 583, -583, 2649, -2649,
    1637, -1637, 723, -723, 2288, -2288, 1100, -1100,
    1409, -1409, 2662, -2662, 3281, -3281, 233, -233,
    756, -756, 2156, -2156, 3015, -3015, 3050, -3050,
    1703, -1703, 1651, -1651, 2789, -2789, 1789, -1789,
    1847, -1847, 952, -952, 1461, -1461, 2687, -2687,
    939, -939, 2308, -2308, 2437, -2437, 2388, -2388,
    733, -733, 2337, -2337, 268, -268, 641, -641,
    1584, -1584, 2298, -2298, 2037, -2037, 3220, -3220,
    375, -375, 2549, -2549, 2090, -2090, 1645, -1645,
    1063, -1063, 319, -319, 2773, -2773, 757, -757,
    2099, -2099, 561, -561, 2466, -2466, 2594, -2594,
    2804, -2804, 1092, -1092, 403, -403, 1026, -1026,
    1143, -1143, 2150, -2150, 2775, -2775, 886, -886,
    1722, -1722, 1212, -1212, 1874, -1874, 1029, -1029,
    2110, -2110, 2935, -2935, 885, -885, 2154, -2154
]

def BitRev7(r):
    reversed_r = 0

    for i in range(7):
        bit = (r >> i) & 1
        reversed_r |= (bit << (6 - i))

    return reversed_r

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
    return SHAKE128.new()

def xof_absorb(ctx, data):
    ctx.update(data)
    return ctx

def xof_squeeze(ctx, z):
    output = ctx.read(z)
    return ctx, output

# Converts a bit array (of a length that is a multiple of eight) into an array of bytes.
def BitsToBytes(b):
    l = len(b) // 8
    B = bytearray(l)
    
    for i in range(8 * l):
        B[i // 8] += b[i] << (i % 8)

    return B

# Performs the inverse of BitsToBytes, converting a byte array into a bit array.
def BytesToBits(B):
    l = len(B)
    b = bytearray(8 * l)

    for i in range(l):
        C = B[i]

        for j in range(8):
            b[i * 8 + j] = C % 2
            C //= 2

    return b

# The Compress and Decompress algorithms satisfy two important properties.
# First, decompression followed by compression preserves the input.
# Second, if 𝑑 is large (i.e., close to 12), compression followed by decompression does not significantly alter the value.
def compress(x, d):
    return [round((2 ** d / params.q) * element) % (2 ** d) for element in x]

def decompress(y, d):
    return [round((params.q / (2 ** d)) * element) for element in y]

# Encodes an array of 𝑑-bit integers into a byte array for 1 ≤ 𝑑 ≤ 12.
def ByteEncode(F, d):
    if type(F[0]) == list:
        b = b''

        for f in F:
            b += ByteEncode(f, d)

        return b

    B = bytearray(256 * d)
    m = 2 ** d if d < 12 else params.q

    for i in range(256):
        a = F[i] % m

        for j in range(d):
            bit = a % 2
            B[i * d + j] = bit
            a = (a - bit) // 2
        
    return BitsToBytes(B)

# Decodes a byte array into an array of 𝑑-bit integers for 1 ≤ 𝑑 ≤ 12.
def ByteDecode(B, d):
    b = BytesToBits(B)
    m = 2**d if d < 12 else params.q
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

        if d1 < params.q:
            a_hat[j] = d1
            j += 1

        if d2 < params.q and j < 256:
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
        f[i] = (x - y) % params.q

    return f

# Computes the NTT representation 𝑓_hat of the given polynomial 𝑓 ∈ 𝑅_𝑞.
def NTT(f):
    f_hat = f[:]
    i = 1

    length = 128

    while length >= 2:
        for start in range(0, 256, 2 * length):
            omega = pow(params.zeta, BitRev7(i), params.q)
            i += 1

            for j in range(start, start + length):
                t = omega * f_hat[j + length] % params.q
                f_hat[j + length] = (f_hat[j] - t) % params.q 
                f_hat[j] = (f_hat[j] + t) % params.q

        length //= 2

    return f_hat

# Computes the polynomial 𝑓 ∈ 𝑅_𝑞 that corresponds to the given NTT representation 𝑓_hat ∈ 𝑇_𝑞.
def NTT_inv(f_hat):
    f = f_hat[:]
    i = 127

    length = 2

    while length <= 128:
        for start in range(0, 256, 2 * length):
            zeta = pow(17, BitRev7(i), params.q)
            i -= 1

            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % params.q
                f[j + length] = zeta * (f[j + length] - t) % params.q

        length *= 2

    f = [(x * 3303) % params.q for x in f]
    
    return f

def MultiplyNTTs(f_hat, g_hat):
    h = [0] * 256

    for i in range(128):
        h[2 * i], h[2 * i + 1] = BaseCaseMultiply(
            f_hat[2 * i], f_hat[2 * i + 1], g_hat[2 * i], g_hat[2 * i + 1], TwoBitRev7_values[i]
        )

    return h

def BaseCaseMultiply(a0, a1, b0, b1, gamma):
    c0 = (a0 * b0 + a1 * b1 * gamma) % params.q
    c1 = (a0 * b1 + a1 * b0) % params.q
    return c0, c1

def AddPolynomials(p1, p2):
    return [(p1[n] + p2[n]) % params.q for n in range(len(p1))]

def SubtractPolynomials(p1, p2):
    return [(p1[n] - p2[n]) % params.q for n in range(len(p1))]