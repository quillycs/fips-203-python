import parameter_sets as params
from Crypto.Hash import SHAKE128
from Crypto.Hash import SHAKE256
import hashlib

BitRev7_values = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848,
    1062, 1919, 193, 797, 2786, 3260, 569, 1746,
    296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
    1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
    289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
    650, 1977, 2513, 632, 2865, 33, 1320, 1915,
    2319, 1435, 807, 452, 1438, 2868, 1534, 2402,
    2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
    17, 2761, 583, 2649, 1637, 723, 2288, 1100,
    1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
    939, 2308, 2437, 2388, 733, 2337, 268, 641,
    1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
    1063, 319, 2773, 757, 2099, 561, 2466, 2594,
    2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
    1722, 1212, 1874, 1029, 2110, 2935, 885, 2154
]

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

def G(c):
    """
    This algorithm can be found in section 4.5 of the FIPS 203 document.
    
    The function G takes one variable-length input and produces two 32-byte outputs. It will be denoted by G : B* → B^32 x B^32. The two outputs of G will be denoted (a, b) ← G(c), where a, b ∈ B^32, c ∈ B*, and G(c) = a || b. The function G shall be instantiated as: G(c) := SHA3-512(c).
    
    Input:
    - c (bytes): The input data to be hashed.
    
    Output:
    - tuple: A tuple containing two 32-byte outputs derived from the SHA3-512 hash of the input.
    """
    
    hash_output = hashlib.sha3_512(c).digest()
    a = hash_output[:32]
    b = hash_output[32:]

    return a, b

"""
The following three algorithms can be found in section 4.6 of the FIPS 203 document.

eXtendable-Output Function (XOF). This standard uses a XOF wrapper defined in terms of the incremental API for SHAKE128 in SP 800-185. This SHAKE128 API consists of three functions:
"""
def xof_init():
    """
    ctx ← SHAKE128.Init(): Initializes a XOF “context” ctx.
    
    Output:
    - SHAKE128_XOF: A new SHAKE128 context.
    """
    
    return SHAKE128.new()

def xof_absorb(ctx, data):
    """
    ctx ← SHAKE128.Absorb(ctx,str): Injects data to be used in the “absorbing” phase of SHAKE128 and updates the context accordingly.
    
    Input:
    - ctx (SHAKE128_XOF): The SHAKE128 context.
    - data (bytes): The data to be absorbed.
    
    Output:
    - SHAKE128_XOF: The updated SHAKE128 context.
    """
    
    ctx.update(data)
    return ctx

def xof_squeeze(ctx, z):
    """
    (ctx,B) ← SHAKE128.Squeeze(ctx, 8 ⋅ z): Extracts z output bytes produced during the “squeezing” phase of SHAKE128 and updates the context accordingly.
    
    Input:
    - ctx (SHAKE128_XOF): The SHAKE128 context.
    - z (int): The number of bytes to extract.
    
    Output:
    - tuple: The updated SHAKE128 context and the extracted output bytes.
    """
    
    output = ctx.read(z)
    return ctx, output

def SampleNTT(B):
    """
    This is algorithm 7 from the FIPS 203 document.
    
    Takes a 32-byte seed as input and outputs a pseudorandom element of T_q.
    
    Input:
    - byte array B ∈ B^34: a 32-byte seed along with two indices
    
    Output:
    - array a_hat ∈ Z_q^256: the coefficients of the NTT of a polynomial
    """
    
    ctx = xof_init()
    ctx = xof_absorb(ctx, B) # input the given byte array into XOF
    j = 0
    a_hat = [0] * 256

    while j < 256:
        ctx, C = xof_squeeze(ctx, 3) # get a fresh 3-byte array 𝐶 from XOF
        
        d1 = C[0] + 256 * (C[1] % 16) # 0 <= d1 < 2^12
        d2 = (C[1] // 16) + 16 * C[2] # 0 <= d2 < 2^12

        if d1 < params.q:
            a_hat[j] = d1 # a_hat ∈ Z_q^256
            j += 1

        if d2 < params.q and j < 256:
            a_hat[j] = d2
            j += 1

    return a_hat

def PRF(eta, s, b):
    """
    This algorithm can be found in sections 4.2 and 4.3 of the FIPS 203 document.
    
    The function PRF takes a parameter 𝜂 ∈ {2, 3}, one 32-byte input, and one 1-byte input. It produces one (64 ⋅ 𝜂)-byte output. It will be denoted by PRF : {2, 3} x B^32 x B → B^(64𝜂), and it shall be instantiated as PRF(𝜂, s, b) := SHAKE256(s || b, 8 x 64 x 𝜂), where 𝜂 ∈ {2, 3}, s ∈ B^32, and b ∈ B.
    
    Input:
    - eta (int): A parameter that determines the output length (𝜂 ∈ {2, 3}).
    - s (bytes): A 32-byte input seed.
    - b (int): A 1-byte input value.
    
    Output:
    - bytes: A (64 * eta)-byte pseudorandom output.
    """
    
    input_data = s + bytes([b])
    shake = SHAKE256.new()
    shake.update(input_data)
    output = shake.read(64 * eta)
    
    return output

def SamplePolyCBD(B, eta):
    """
    This is algorithm 8 from the FIPS 203 document.
    
    Takes a seed as input and outputs a pseudorandom sample from the distribution D_𝜂(R_q).
    
    Input:
    - byte array B ∈ B^(64 x 𝜂).
    - eta (int): A parameter that controls the sampling distribution.
    
    Output:
    - array f ∈ Z_q^256: the coefficients of the sampled polynomial
    """
    
    b = BytesToBits(B)
    f = [0] * 256

    for i in range(256):
        x = sum(b[2 * i * eta + j] for j in range(eta)) # 0 <= x <= eta
        y = sum(b[2 * i * eta + eta + j] for j in range(eta)) # 0 <= y <= eta
        f[i] = (x - y) % params.q # 0 <= f[i] <= eta or q - eta <= f[i] <= q - 1

    return f

def NTT(f):
    """
    This is algorithm 9 from the FIPS 203 document.
    
    Computes the NTT representation f_hat of the given polynomial f ∈ R_q.
    
    Parameters:
    - array f ∈ Z_q^256: the coefficients of the input polynomial
    
    Returns:
    - array f_hat ∈ Z_q^256: the coefficients of the NTT of the input polynomial
    """
    
    f_hat = f[:] # will compute in place on a copy of input array
    i = 1
    length = 128 

    while length >= 2:
        for start in range(0, 256, 2 * length):
            omega = BitRev7_values[i] % params.q
            i += 1

            for j in range(start, start + length):
                t = omega * f_hat[j + length] % params.q
                f_hat[j + length] = (f_hat[j] - t) % params.q 
                f_hat[j] = (f_hat[j] + t) % params.q

        length //= 2

    return f_hat

def BaseCaseMultiply(a0, a1, b0, b1, gamma):
    """
    This is algorithm 12 from the FIPS 203 document.
    
    Computes the product of two degree-one polynomials with respect to a quadratic modulus.
    
    Input:
    - a0, a1, b0, b1 ∈ Z_q: the coefficients of a0 + a1X and b0 + b1X
    - gamma ∈ Z_q: the modulus is X^2 - gamma
    
    Output:
    - c0, c1 ∈ Z_q: the coefficients of the product of the two polynomials
    """
    
    c0 = (a0 * b0 + a1 * b1 * gamma) % params.q
    c1 = (a0 * b1 + a1 * b0) % params.q
    
    return c0, c1

def MultiplyNTTs(f_hat, g_hat):
    """
    This is algorithm 11 from the FIPS 203 document.
    
    Computes the product (in the ring T_q) of two NTT representations.
    
    Input:
    - Two arrays f_hat ∈ Z_q^256 and g_hat ∈ Z_q^256: the coefficients of two NTT representations
    
    Output:
    - An array h ∈ Z_q^256: the coefficients of the product of the inputs
    """
    
    h = [0] * 256

    for i in range(128):
        h[2 * i], h[2 * i + 1] = BaseCaseMultiply(
            f_hat[2 * i], f_hat[2 * i + 1], g_hat[2 * i], g_hat[2 * i + 1], TwoBitRev7_values[i]
        )

    return h

def BitsToBytes(b):
    """
    This is algorithm 3 from the FIPS 203 document.
    
    Converts a bit array (of a length that is a multiple of eight) into an array of bytes.
    
    Input:
    - bit array b ∈ {0, 1}^(8 * l).
    
    Output:
    - byte array B ∈ B^l.
    """
    
    l = len(b) // 8
    B = bytearray(l)
    
    for i in range(8 * l):
        B[i // 8] += b[i] << (i % 8)

    return B

def ByteEncode(F, d):
    """
    This is algorithm 5 from the FIPS 203 document.
    
    Encodes an array of d-bit integers into a byte array for 1 ≤ d ≤ 12.
    
    Input:
    - integer array F ∈ Z_m^256, where m = 2^d if d < 12, and m = q if d = 12.
    
    Output:
    - byte array B ∈ B^(32 * d).
    """

    if type(F[0]) == list:
        b = b''

        for f in F:
            b += ByteEncode(f, d)

        return b

    B = bytearray(256 * d)
    m = 2 ** d if d < 12 else params.q

    for i in range(256):
        a = F[i] % m # a ∈ Z_m

        for j in range(d):
            bit = a % 2
            B[i * d + j] = bit # b ∈ {0, 1}^(256 * d)
            a = (a - bit) // 2 # note 𝑎−𝑏[𝑖 x 𝑑 + 𝑗] is always even
    
    return BitsToBytes(B)

def BytesToBits(B):
    """
    This is algorithm 4 from the FIPS 203 document.
    
    Performs the inverse of BitsToBytes, converting a byte array into a bit array.
    
    Input:
    - byte array B ∈ B^l
    
    Output:
    - bit array b ∈ {0, 1}^(8 * l)
    """
    
    l = len(B)
    b = bytearray(8 * l)

    for i in range(l):
        C = B[i]

        for j in range(8):
            b[i * 8 + j] = C % 2
            C //= 2

    return b

def ByteDecode(B, d):
    """
    This is algorithm 6 from the FIPS 203 document.
    
    Decodes a byte array into an array of d-bit integers for 1 ≤ d ≤ 12.
    
    Input:
    - byte array B ∈ B^(32 * d).
    
    Output:
    - integer array F ∈ Z_m^256, where m = 2^d if d < 12 and m = q if d = 12.
    """
    
    b = BytesToBits(B)
    m = 2**d if d < 12 else params.q
    F = [0] * 256

    for i in range(256):
        F[i] = sum(b[i * d + j] * (2**j) for j in range(d)) % m

    return F

def AddPolynomials(p1, p2):
    """
    Helper function that adds two polynomials coefficient-wise modulo q.
    
    Input:
    - p1 (list of int): The first polynomial represented as a list of coefficients.
    - p2 (list of int): The second polynomial represented as a list of coefficients.
    
    Output:
    - list of int: The resulting polynomial after addition, with coefficients modulo q.
    """
    
    return [(p1[n] + p2[n]) % params.q for n in range(len(p1))] # element-wise addition modulo q

def NTT_inv(f_hat):
    """
    This is algorithm 10 from the FIPS 203 document.
    
    Computes the polynomial f ∈ R_q that corresponds to the given NTT representation f_hat ∈ T_q.
    
    Input:
    - array f_hat ∈ Z_q^256: the coefficients of input NTT representation
    
    Output:
    - array f ∈ Z_q^256: the coefficients of the inverse NTT of the input
    """
    
    f = f_hat[:] # will compute in place on a copy of input array
    i = 127
    length = 2

    while length <= 128:
        for start in range(0, 256, 2 * length):
            zeta = BitRev7_values[i] % params.q
            i -= 1

            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % params.q
                f[j + length] = zeta * (f[j + length] - t) % params.q

        length *= 2

    f = [(x * 3303) % params.q for x in f] # multiply every entry by 3303 ≡ 128^-1 mod q
    
    return f

"""
The following two algorithms, compress and decompress, can be found in sections 4.7 and 4.8 of the FIPS 203 document, respectively.

The Compress and Decompress algorithms satisfy two important properties. First, decompression followed by compression preserves the input. That is, Compress(Decompress(y)) = 𝑦 for
all y ∈ Z_(2^d) and all d < 12. Second, if d is large (i.e., close to 12), compression followed by decompression does not significantly alter the value.
"""

def compress(x, d):
    """
    Compresses a list of integers by mapping them to a smaller range.
    
    Input:
    - x (list of int): The input list of integers.
    - d (int): The compression parameter (d < 12).
    
    Output:
    - list of int: The compressed representation of the input list.
    """
    
    return [round((2 ** d / params.q) * element) % (2 ** d) for element in x]

def decompress(y, d):
    """
    Decompresses a list of integers back to their approximate original values.
    
    Input:
    - y (list of int): The compressed list of integers.
    - d (int): The compression parameter (d < 12).
    
    Output:
    - list of int: The decompressed representation of the input list.
    """
    
    return [round((params.q * element + (1 << (d - 1))) / (2 ** d)) for element in y]

def SubtractPolynomials(p1, p2):
    """
    Helper function that subtracts two polynomials coefficient-wise modulo q.
    
    Input:
    - p1 (list of int): The first polynomial represented as a list of coefficients.
    - p2 (list of int): The second polynomial represented as a list of coefficients.
    
    Output:
    - list of int: The resulting polynomial after subtraction, with coefficients modulo q.
    """
    
    return [(p1[n] - p2[n]) % params.q for n in range(len(p1))] # element-wise subtraction modulo q

"""
The following two algorithms, H and J, can be found in section 4.4 of the FIPS 203 document, respectively.

The functions H and J each take one variable-length input and produce one 32-byte output. They will be denoted by H : B* → B^32 and J : B* → B^32. The functions H and J shall be instantiated as: H(s) := SHA3-256(s) and J(s) := SHAKE256(s) where s ∈ B*.
"""
def H(s):
    """
    Computes the SHA3-256 hash of the input.
    
    Input:
    - s (bytes): The input data.
    
    Output:
    - bytes: A 32-byte hash output.
    """
    
    return hashlib.sha3_256(s).digest()

def J(s):
    """
    Computes the SHAKE256 hash of the input, producing a 32-byte output.
    
    Input:
    - s (bytes): The input data.
    
    Output:
    - bytes: A 32-byte hash output.
    """
    
    return SHAKE256.new(s).read(32)