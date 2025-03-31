import auxiliary_algorithms as aux
import parameter_sets as params

def keygen(d):
    """
    This is algorithm 13 from the FIPS 203 document.
    
    Input:
    - randomness d ∈ B^32.
    
    Output:
    - encryption key ek_pke ∈ B^(384k + 32).
    - decryption key dk_pke ∈ B^(384k)
    """
    
    rho, sigma = aux.G(d + bytes([params.k])) # expand 32+1 bytes to two pseudorandom 32-byte seeds
    N = 0

    A = []

    for i in range(params.k): # generate matrix A_hat ∈ (Z_q^256)^(k x k)
        row = []

        for j in range(params.k):
            B = rho + bytes([j, i]) # 𝑗 and 𝑖 are bytes 33 and 34 of the input
            row.append(aux.SampleNTT(B))

        A.append(row)

    s = []

    for i in range(params.k): # generate s ∈ (Z_q^256)^k
        prf_output = aux.PRF(params.eta1, sigma, N)
        s.append(aux.SamplePolyCBD(prf_output, params.eta1)) # s[i] ∈ Z_q^256 sampled from CBD
        N += 1

    e = []

    for i in range(params.k): # generate e ∈ (Z_q^256)^k
        prf_output = aux.PRF(params.eta1, sigma, N)
        e.append(aux.SamplePolyCBD(prf_output, params.eta1)) # e[i] ∈ Z_q^256 sampled from CBD
        N += 1

    s_hat = [aux.NTT(x) for x in s] # run NTT k times (once for each coordinate of s)
    e_hat = [aux.NTT(y) for y in e] # run NTT k times

    t = []

    for i in range(params.k): # noisy linear system in NTT domain
        t.append([0] * 256)
        
        for j in range(params.k):
            product = aux.MultiplyNTTs(A[i][j], s_hat[j])
            t[i] = aux.AddPolynomials(t[i], product)
        
        t[i] = aux.AddPolynomials(t[i], e_hat[i])

    ekPKE = b"".join(aux.ByteEncode(t_i, 12) for t_i in t) + rho # run ByteEncode k times, then append A_hat-seed
    dkPKE = b"".join(aux.ByteEncode(s_hat_i, 12) for s_hat_i in s_hat) # run ByteEncode k times
    
    return (ekPKE, dkPKE)

def encrypt(ekPKE, m, r):
    """
    This is algorithm 14 from the FIPS 203 document.
    
    Uses the encryption key to encrypt a plaintext message using the randomness r.
    
    Input:
    - encryption key ek_pke ∈ B^(384k + 32).
    - message m ∈ B^32.
    - randomness r ∈ B^32.
    
    Output:
    - ciphertext c ∈ B^(32(d_u * k + d_v))
    """
    
    N = 0
    t_hat = [aux.ByteDecode(ekPKE[i * 384:(i + 1) * 384], 12) for i in range(params.k)] # run ByteDecode k times to decode t_hat ∈ (Z_q^256)^k
    
    rho = ekPKE[384 * params.k: 384 * params.k + 32] # extract 32-byte seed from ek_pke

    A_hat = [[aux.SampleNTT(rho + bytes([j, i])) for j in range(params.k)] for i in range(params.k)] # re-generate matrix A_hat ∈ (Z_q^256)^(k x k) sampled in algorithm 13 | j and i are bytes 33 and 34 of the input

    y = [aux.SamplePolyCBD(aux.PRF(params.eta1, r, N + i), params.eta1) for i in range(params.k)] # generate y ∈ (Z_q^256)^k | y[i] ∈ Z_q^256 sampled from CBD
    N += params.k

    e1 = [aux.SamplePolyCBD(aux.PRF(params.eta2, r, N + i), params.eta2) for i in range(params.k)] # generate e1 ∈ (Z_q^256)^k | e1[i] ∈ Z_q^256 sampled from CBD
    N += params.k

    e2 = aux.SamplePolyCBD(aux.PRF(params.eta2, r, N), params.eta2) # sample e2 ∈ Z_q^256 from CBD

    y_hat = [aux.NTT(y_i) for y_i in y] # run NTT k times

    u = [[0] * 256 for _ in range(params.k)]

    for i in range(params.k):
        for j in range(params.k):
            u[i] = aux.AddPolynomials(u[i], aux.MultiplyNTTs(A_hat[j][i], y_hat[j]))

    u = [aux.AddPolynomials(aux.NTT_inv(u[i]), e1[i]) for i in range(params.k)] # run NTT_inv k times

    mu  = aux.decompress(aux.ByteDecode(m, 1), 1)

    v = [0] * 256
    
    for i in range(params.k): 
        v = aux.AddPolynomials(v, aux.MultiplyNTTs(t_hat[i], y_hat[i]))
    
    v = aux.AddPolynomials(aux.NTT_inv(v), e2)
    v = aux.AddPolynomials(v, mu) # encode plaintext m into polynomal v

    c1 = b''.join(aux.ByteEncode(aux.compress(u[i], params.du), params.du) for i in range(params.k)) # run ByteEncode and Compress k times
    c2 = aux.ByteEncode(aux.compress(v, params.dv), params.dv)

    return c1 + c2

def decrypt(dkPKE, c):
    """
    This is algorithm 15 from the FIPS 203 document.
    
    Uses the decryption key to decrypt a ciphertext.
    
    Input:
    - decryption key dk_pke ∈ B^(384k).
    - ciphertext c ∈ B^(32(d_u * k + d_v)).
    
    Output:
    - message m ∈ B^32.
    """
    
    c1 = c[:32 * params.du * params.k]
    c2 = c[32 * params.du * params.k: 32 * (params.du * params.k + params.dv)]

    u_prime = []

    for i in range(params.k):
        decoded = aux.ByteDecode(c1[32 * params.du * i:32 * params.du * (i + 1)], params.du)
        u_prime.append(aux.decompress(decoded, params.du)) # run Decompress and ByteDecode k times

    v_prime = aux.decompress(aux.ByteDecode(c2, params.dv), params.dv)

    s_hat = []

    for i in range(params.k):
        decoded = aux.ByteDecode(dkPKE[384 * i : 384 * (i + 1)], 12) # run ByteDecode k times
        s_hat.append(decoded)

    w   = [0] * 256

    for i in range(params.k):
        w = aux.AddPolynomials(w, aux.MultiplyNTTs(s_hat[i], aux.NTT(u_prime[i])))

    w = aux.SubtractPolynomials(v_prime, aux.NTT_inv(w)) # run NTT k times; run NTT_inv once
    
    m = aux.ByteEncode(aux.compress(w, 1), 1) # decode plaintext m from polynomial v

    return m