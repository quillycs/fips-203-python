import auxiliary_algorithms as aux
import parameter_set as params

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

    s_hat = [aux.NTT(s[i]) for s_i in s]
    e_hat = [aux.NTT(e[i]) for e_i in e]

    t = []

    for i in range(params.k):
        t_row = [sum(A[i][j][n] * s_hat[j][n] % params.q for j in range(params.k)) % params.q for n in range(256)]
        t.append([(t_row[n] + e_hat[i][n]) % params.q for n in range(256)])

    ekPKE = b"".join(aux.ByteEncode(t_i, 12) for t_i in t) + rho
    dkPKE = b"".join(aux.ByteEncode(s_hat_i, 12) for s_hat_i in s_hat)
    
    return ekPKE, dkPKE

def encrypt(ekPKE, m, r):
    N = 0
    t_hat = [aux.ByteEncode(ekPKE[i * 384:(i + 1) * 384], 12) for i in range(params.k)]
    rho = ekPKE[384 * params.k: 384 * params.k + 32]

    A_hat = [[aux.SampleNTT(rho + bytes([j, i])) for j in range(params.k)] for i in range(params.k)]

    y = [aux.SamplePolyCBD(aux.PRF(params.eta1, r, N), params.eta1) for _ in range(params.k)]
    N += params.k

    e1 = [aux.SamplePolyCBD(aux.PRF(params.eta2, r, N), params.eta2) for _ in range(params.k)]
    N += params.k

    e2 = aux.SamplePolyCBD(aux.PRF(params.eta2, r, N), params.eta2)

    y_hat = [aux.NTT(y_i) for y_i in y]

    u = [aux.NTT_inv([(sum(A_hat[j][i][n] * y_hat[j][n] % params.q for j in range(params.k)) + e1[i][n]) % params.q for n in range(256)]) for i in range(params.k)]

    mu = aux.ByteDecode(m, 1)
    mu = [aux.decompress(val, 1) for val in mu]

    v = [(sum(t_hat[i][n] * y_hat[i][n] % params.q for i in range(params.k)) + e2[n] + mu[n]) % params.q for n in range(256)]

    c1 = b"".join(aux.ByteEncode([aux.compress(u_i[n], params.du) for n in range(256)], params.du) for u_i in u)
    c2 = aux.ByteEncode([aux.compress(v[n], params.dv) for n in range(256)], params.dv)

    return c1 + c2

'''
def decrypt(dkPKE, c):
    c1 = c[:32 * self.du * self.k]
    c2 = c[32 * self.du * self.k:32 * (self.du * self.k + self.dv)]

    u_prime = [decompress(ByteDecode(c1[i * 384:(i + 1) * 384], self.du), self.du) for i in range(self.k)]
'''

d = b'\x01' * 32
ekPKE, dkPKE = keygen(d)
message = b'\x01' * 32
randomness = b'\x02' * 32
ciphertext = encrypt(ekPKE, message, randomness)
print("Ciphertext:")
print(ciphertext)