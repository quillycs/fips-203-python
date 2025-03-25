import auxiliary_algorithms as aux
import parameter_sets as params

def keygen(d):
    rho, sigma = aux.G(d + bytes([params.k]))
    N = 0

    A = []

    for i in range(params.k):
        row = []

        for j in range(params.k):
            B = rho + bytes([j, i])
            row.append(aux.SampleNTT(B))

        A.append(row)

    s = []

    for i in range(params.k):
        prf_output = aux.PRF(params.eta1, sigma, N)
        s.append(aux.SamplePolyCBD(prf_output, params.eta1))
        N += 1

    
    e = []

    for i in range(params.k):
        prf_output = aux.PRF(params.eta1, sigma, N)
        e.append(aux.SamplePolyCBD(prf_output, params.eta1))
        N += 1

    s_hat = [aux.NTT(x) for x in s]
    e_hat = [aux.NTT(y) for y in e]

    t = []

    for i in range(params.k):
        t.append([0] * 256)

        for j in range(params.k):
            product = aux.MultiplyNTTs(A[i][j], s_hat[j])

            for n in range(256):
                t[i][n] = (t[i][n] + product[n]) % params.q

        for n in range(256):
            t[i][n] = (t[i][n] + e_hat[i][n]) % params.q

    ekPKE = b"".join(aux.ByteEncode(t_i, 12) for t_i in t) + rho
    dkPKE = b"".join(aux.ByteEncode(s_hat_i, 12) for s_hat_i in s_hat)
    
    return (ekPKE, dkPKE)

def encrypt(ekPKE, m, r):
    N = 0
    t_hat = [aux.ByteDecode(ekPKE[i * 384:(i + 1) * 384], 12) for i in range(params.k)]
    
    rho = ekPKE[384 * params.k: 384 * params.k + 32]

    A_hat = [[aux.SampleNTT(rho + bytes([j, i])) for j in range(params.k)] for i in range(params.k)]

    y = [aux.SamplePolyCBD(aux.PRF(params.eta1, r, N + i), params.eta1) for i in range(params.k)]
    N += params.k

    e1 = [aux.SamplePolyCBD(aux.PRF(params.eta2, r, N + i), params.eta2) for i in range(params.k)]
    N += params.k

    e2 = aux.SamplePolyCBD(aux.PRF(params.eta2, r, N), params.eta2)

    y_hat = [aux.NTT(y_i) for y_i in y]

    u = [[0] * 256 for _ in range(params.k)]

    for i in range(params.k):
        for j in range(params.k):
            u[i] = aux.AddPolynomials(u[i], aux.MultiplyNTTs(A_hat[j][i], y_hat[j]))

    u = [aux.AddPolynomials(aux.NTT_inv(u[i]), e1[i]) for i in range(params.k)]

    mu  = aux.decompress(aux.ByteDecode(m, 1), 1)

    v = [0] * 256
    
    for i in range(params.k): 
        v = aux.AddPolynomials(v, aux.MultiplyNTTs(t_hat[i], y_hat[i]))
    
    v = aux.AddPolynomials(aux.NTT_inv(v), e2)
    v = aux.AddPolynomials(v, mu)

    c1 = b''.join(aux.ByteEncode(aux.compress(u[i], params.du), params.du) for i in range(params.k))
    c2 = aux.ByteEncode(aux.compress(v, params.dv), params.dv)

    return c1 + c2

'''def encrypt(ek_pke, m, r):
    n   = 0
    t   = [ aux.ByteDecode(ek_pke[384*i:384*(i+1)], 12) for i in range(params.k) ]
    rho = ek_pke[384*params.k : 384*params.k + 32]
    a   = [ [None]*params.k for _ in range(params.k) ]
    for i in range(params.k):
        for j in range(params.k):
            a[i][j] = aux.SampleNTT(rho + bytes([j, i]))

    y = [None]*params.k
    for i in range(params.k):
        y[i] = aux.SamplePolyCBD(aux.PRF(params.eta1, r, n), params.eta1)
        n   += 1
    # print('# y:"', y)
    e1 = [None]*params.k
    for i in range(params.k):
        e1[i] = aux.SamplePolyCBD(aux.PRF(params.eta2, r, n), params.eta2)
        n += 1
    # print('# e1:"', e1)
    e2 = aux.SamplePolyCBD(aux.PRF(params.eta2, r, n), params.eta2)
    # print('# e2:"', e2)
    y   = [ aux.NTT(v) for v in y ]
    # print('# yHat:"', y)
    u   = [ [0]*256 for _ in range(params.k) ]
    for i in range(params.k):
        for j in range(params.k):
            u[i] = aux.AddPolynomials(u[i], aux.MultiplyNTTs(a[j][i], y[j]))
    # print('# AHat^T*yHat:"', u)
    for i in range(params.k):
        u[i] = aux.NTT_inv(u[i])
        u[i] = aux.AddPolynomials(u[i], e1[i])
    # print('# u:', u);

    mu  = aux.decompress(aux.ByteDecode(m, 1), 1)
    # print('# mu:', mu);

    v   = [0]*256
    for i in range(params.k):
        v = aux.AddPolynomials(v, aux.MultiplyNTTs(t[i], y[i]))
    # print('# tHat^T*yHat:', v)
    v   = aux.NTT_inv(v)
    # print('# NTTInverse(tHat^T*yHat):', v)
    v   = aux.AddPolynomials(v, e2)
    v   = aux.AddPolynomials(v, mu)
    # print('# v:', v)
    c1  = b''
    for i in range(params.k):
        c1 += aux.ByteEncode(aux.compress(u[i], params.du), params.du)
    c2  = aux.ByteEncode(aux.compress(v, params.dv), params.dv)
    c   = c1 + c2
    return c'''

def decrypt(dkPKE, c):
    c1 = c[:32 * params.du * params.k]
    c2 = c[32 * params.du * params.k: 32 * (params.du * params.k + params.dv)]

    u_prime = []

    for i in range(params.k):
        decoded = aux.ByteDecode(c1[32 * params.du * i:32 * params.du * (i + 1)], params.du)
        u_prime.append(aux.decompress(decoded, params.du))

    v_prime = aux.decompress(aux.ByteDecode(c2, params.dv), params.dv)

    s_hat = []

    for i in range(params.k):
        decoded = aux.ByteDecode(dkPKE[384 * i : 384 * (i + 1)], 12)
        s_hat.append(decoded)

    w   = [0] * 256

    for i in range(params.k):
        w = aux.AddPolynomials(w, aux.MultiplyNTTs(s_hat[i], aux.NTT(u_prime[i])))

    w = aux.SubtractPolynomials(v_prime, aux.NTT_inv(w))
    
    m = aux.ByteEncode(aux.compress(w, 1), 1)

    return m