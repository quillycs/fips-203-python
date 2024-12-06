import hashlib
import random
import os

# Constant
zeta = 17

class KPKE:
    def __init__(self, n, q, k, eta1, eta2, du, dv):
        self.n = n
        self.q = q
        self.k = k
        self.eta1 = eta1
        self.eta2 = eta2
        self.du = du
        self.dv = dv

    def keygen(self, d):
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
            prf_output = PRF(eta1, sigma, N)
            s.append(SamplePolyCBD(prf_output, eta1))
            N += 1

        e = []

        for i in range(k):
            prf_output = PRF(eta1, sigma, N)
            e.append(SamplePolyCBD(prf_output, eta1))
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

    def encrypt(self, ekPKE, m, r):
        N = 0
        t_hat = [ByteEncode(ekPKE[i * 384:(i + 1) * 384], 12) for i in range(k)]
        rho = ekPKE[384 * k: 384 * k + 32]

        A_hat = [[SampleNTT(rho + bytes([j, i])) for j in range(k)] for i in range(k)]

        y = [SamplePolyCBD(PRF(eta1, r, N), eta1) for _ in range(k)]
        N += k

        e1 = [SamplePolyCBD(PRF(eta2, r, N), eta2) for _ in range(k)]
        N += k

        e2 = SamplePolyCBD(PRF(eta2, r, N), eta2)

        y_hat = [NTT(y_i) for y_i in y]

        u = [NTT_inv([(sum(A_hat[j][i][n] * y_hat[j][n] % q for j in range(k)) + e1[i][n]) % q for n in range(256)]) for i in range(k)]

        mu = ByteDecode(m, 12)
        mu = decompress(mu, 12)

        v = [(sum(t_hat[i][n] * y_hat[i][n] % q for i in range(k)) + e2[n] + mu[n]) % q for n in range(256)]

        c1 = b"".join(ByteEncode([compress(u_i[n], du) for n in range(256)], du) for u_i in u)
        c2 = ByteEncode([compress(v[n], dv) for n in range(256)], dv)

        return c1 + c2

    def decrypt(self, dkPKE, c):
        c1 = c[:32 * self.du * self.k]
        c2 = c[32 * self.du * self.k:32 * (self.du * self.k + self.dv)]

        u_prime = [decompress(ByteDecode(c1[i * 384:(i + 1) * 384], self.du), self.du) for i in range(self.k)]