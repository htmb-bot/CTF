---
# Winternitz is coming

| Chal info | FCSC2024 |
| ------ | ----------- |
| Name | Winternitz is coming |
| Category   | Crypto |
| Difficulty | :star: :star: |
| Number of solves | ? |
| Type | Lattice attack - Winternitz signature |
| Writeup by | htmb |

Below is the challenge code.

``` py
import os
from ast import literal_eval
from hashlib import sha256

class WiC:

    def __init__(self, W = 257, msglen = 20, siglen = 40):
        # Parameters
        self.W = W
        self.msglen = msglen
        self.siglen = siglen

        self.n1 = self.siglen // 256 + 1
        self.n2 = self.W // 256 + 1

        # Evaluation points chosen uniformly at random
        self.Support = [
              8,  17,  26,  32,  52,  53,  57,  58,
             59,  63,  64,  66,  67,  71,  73,  76,
             79,  81, 111, 115, 132, 135, 141, 144,
            151, 157, 170, 176, 191, 192, 200, 201,
            202, 207, 216, 224, 228, 237, 241, 252,
        ]

        # Run key generation
        self._keygen()

    def _keygen(self):
        sk_seed = os.urandom(16)
        mask_seed = os.urandom(16)

        SK = [
            sha256(sk_seed + i.to_bytes(self.n1)).digest()
            for i in range(self.siglen)
        ]
        PK = SK.copy()
        for i in range(self.siglen):
            for j in range(1, self.W):
                PK[i] = self._H(PK[i], mask_seed, i, j)

        self.sk = (mask_seed, sk_seed)
        self.pk = (mask_seed, PK)

    def _byte_xor(self, b1, b2):
        assert len(b1) == len(b2), "Error: byte strings of different length."
        return bytes([x ^ y for x, y in zip(b1, b2)])

    def _encoding(self, msg):
        w = [0] * len(self.Support)
        for i in range(len(self.Support)):
            for j in range(len(msg)):
                # Constant coefficient is zero
                w[i] += msg[j] * self.Support[i] ** (j + 1)
            w[i] %= self.W
        return w

    def _H(self, s, m, i, j):
        return sha256(
            self._byte_xor(
                s,
                sha256(
                    m + i.to_bytes(self.n1) + j.to_bytes(self.n2)
                ).digest()
            )
        ).digest()

    def sign(self, message):
        if len(message) > self.msglen:
            print("Error: message too long.")
            return None

        mask_seed, sk_seed = self.sk

        w = self._encoding(message)
        S = [
            sha256(sk_seed + i.to_bytes(self.n1)).digest()
            for i in range(self.siglen)
        ]
        for i in range(self.siglen):
            for j in range(1, w[i] + 1):
                S[i] = self._H(S[i], mask_seed, i, j)

        return [s.hex() for s in S]

    # message is a list of bytes
    def verif(self, message, signature):
        if len(message) > self.msglen:
            print("Error: message too long.")
            return None

        mask_seed, PK = self.pk

        w = self._encoding(message)
        for i in range(self.siglen):
            for j in range(w[i] + 1, self.W):
                signature[i] = self._H(signature[i], mask_seed, i, j)

        return all(s == pk for s, pk in zip(signature, PK))

S = WiC()
pk = (
    S.pk[0].hex(),
    [ pk.hex() for pk in S.pk[1] ]
)

message = b"WINTERNITZ IS COMING"
signature = S.sign(message)

print (f"{message = }")
print (f"{signature = }")
print (f"{pk = }")

try:
    print("Input your message (hex format):")
    your_message = bytes.fromhex(input(">>> "))

    print("Input your signature (list of hex strings):")
    your_signature = literal_eval(input(">>> "))
    your_signature = [bytes.fromhex(s) for s in your_signature]

    assert message != your_message
    assert len(your_message) == 20
    assert len(your_signature) == 40

    if S.verif(your_message, your_signature):
        print("Congratulations! Here is your flag:")
        print(open("flag.txt").read())
    else:
        print("Not quite, try again!")

except:
    print("Please check your inputs.")

```

This implements a variant of the well known Winternitz One-Time Signature, a pretty clever scheme which we now describe. $H$ denotes a hash function, here it is `sha256`.

- **KeyGen**: The secret key $sk$ consists of $40$ pseudorandom values $(sk_1,\ldots,sk_{40})$ (obtained after hashing iterations of a secret seed). The public key is $pk=(H^{256}(sk_1),\ldots,H^{256}(sk_{40}))$, where $H^a$ denotes $H$ composed $a$ times with itself (Note: the challenge is slightly different as the hash function is different at each step, but we won't concern ourselves with this change).
- **Signature**: Given a $20$-byte message $m$, $m$ is encoded into a $40$-byte $w=(w_1,\ldots,w_{40})$. The signature is $(H^{w_1}(sk_1),\ldots,H^{w_{40}}(sk_{40}))$. The hash function is impossible to invert, so the secret key does not leak.
- **Verification**: Convert $m$ into $w$ via the encoding process, and then apply $H$ $(256-w_i)$ times on the $i$-th component of the signature, for every $i$ between $1$ and $40$. If the result is $pk$, then accept the signature.

The Challenge signs the message `message = b"WINTERNITZ IS COMING"`, and provides us with the signature which we call $s$. We must forge a signature for a different message to get the flag.

My first thought is that if the encoding somehow maps two messages to the same $w$, then a valid signature for the first would also be valid for the other. But this option is soon discarded, as the encoding is obtained by multiplication by a Vandermonde matrix which we call $V$. Indeed $V$ is full-rank (as a matrix with coefficients in $\mathbb{F}_{257}$).

Formally, if $`m \in \mathbb{F}_{257}^{20}`$, then $`w=Vm \in \mathbb{F}_{257}^{40}`$ is its encoding,
where $`V\in{\mathbb{F}_{257}}^{40\times 20}`$ is defined by $`V_{i,j}=S_i^j`$ (where $S=(S_1,\ldots,S_{40})$ is the fixed vector `Support`). 
This linear encoding map is very interesting, as it embedds $`\mathbb{F}_{257}^{20}`$ into a $`20`$-dimensional linear subspace of $`\mathbb{F}_{257}^{40}`$. Let $F$ denote this subspace.

An easy way to forge Winternitz signatures (with no encoding) is to start with a given message-signature pair $(m,s)$, and use the fact that for $k_i>0$ such that $k_i+m_i<257$, $s_i'=H^{k_i}(s_i)=H^{k_i}(H^{m_i}(sk_i))=H^{k_i+m_i}(sk_i)$ gives a partial valid signature for $k_i+m_i$. What prevents us from immediatly using this technique is the encoding: suppose we had a valid vector $k=(k_1,\ldots,k_{40})$ for an encoded message-signature pair $(w,s)$, then $w+k$ would need to be in $F$ in order for there to exist a message $m'$ that encodes to $w+k$, and such that $(m',s')$ would constitute a forgery.

We know $w$ for our message, so the question now become: how does one find a vector $`k\in \mathbb{F}_{257}^{40}\backslash\{0\}`$ such that $w+k\in F$ and $0\le k_i < 257 - w_i$. This can be phrased as a Closest Vector Problem (CVP) in the lattice that spans $F$. Let's call this lattice $L$.

**Description of the CVP lattice**: $L$ is $q$-ary, it is generated by the columns of $V$ as well as the vectors composed of $257$ and only zeros. It has dimension $40$. We can reduce $L$ using LLL, but the lattice might not be fully reduced given the dimension, so to boost our chances we run BKZ-40 to get an HKZ-reduced basis. As a bonus, running LLL first automatically gets rid of the linear dependancies, and speeds up BKZ-40. Note that BKZ-40 should not take more than a few seconds to run.

**Description of the CVP target**: We cannot afford to be careless here. We want to find a lattice vector $w'$ that is such that $k=w-w'$ satisfies all the inequalities above. In particular, $w'=w$ is not a valid solution. If $`K=\{k\in\mathbb{F}_{257}^{40}\backslash\{0\}:\forall 1\le i \le 40, 0\le k_i <257 - w_i \}`$, then we might worry that $K\cap F$ is not large enough, or even empty! Luckily, a probabilistic counting argument tells us that this set should be huge (at least $2^{76}$), we should be fine. Clearly, coordinates with the largest values of $w_i$ offer the least leeway in terms of possible $k$. We can pick a target vector $t$ where $t_i$ is between $0$ and $257-w_i$, for example $t_i\approx \frac{257-w_i}{2}$ and use Babai's Nearest Plane algorithm to solve the CVP. For better results we use a randomised target, where the random offset is proportional to the coordinates $257-w_i$. This shouldn't fail but if it does then we can always rely on lattice enumeration, so we're pretty confident that we will get the flag now.


Here is the code, in SageMath.

```py
import random as rd
from fpylll import IntegerMatrix,BKZ
from hashlib import sha256

def _byte_xor(b1, b2): #From chall code
    assert len(b1) == len(b2), "Error: byte strings of different length."
    return bytes([x ^^ y for x, y in zip(b1, b2)])

def _H(s, m, i, j): #From chall code
    return sha256(_byte_xor(s, sha256(m + i.to_bytes(1) + j.to_bytes(2)).digest())).digest()

Support = [
              8,  17,  26,  32,  52,  53,  57,  58,
             59,  63,  64,  66,  67,  71,  73,  76,
             79,  81, 111, 115, 132, 135, 141, 144,
            151, 157, 170, 176, 191, 192, 200, 201,
            202, 207, 216, 224, 228, 237, 241, 252,
        ]

def BKZ_red(M,beta,tours=0): #Stronger lattice reduction
    """BKZ with blocksize beta"""
    M = IntegerMatrix.from_matrix(M)
    M = Matrix(BKZ.reduction(M, BKZ.Param(beta,max_loops=tours)))
    return M

def dot(A,B):
    return(sum([A[i]*B[i] for i in range(len(A))]))    

def Babai_NP(M, G, target): #Babai's Nearest Plane
    '''Computes a vector of the lattice M that is close to target, using the gram_schmidt matrix G'''
    small = target
    for i in reversed(range(M.nrows())):
        c = (dot(small,G[i]) / dot(G[i],G[i])).round()
        small -=  c * M[i]
    return target - small

message = b"WINTERNITZ IS COMING"
m = vector(message)

V = Matrix(ZZ,[[Support[i]**(j+1) for j in range(20)] for i in range(40)]) #Vandermonde matrix
w = V*m % 257 # compute encoding

L = list(V.transpose())
for i in range(40):
    L.append([0]*i+[257]+[0]*(39-i))
L = Matrix(L) #q-ary lattice
print("Lattice initialised")
Lred = L.LLL()[20:] #Setting up CVP, the first 20 rows are empty
Lred = Matrix(BKZ_red(Lred,40)) #HKZ-reduce 
print("Lattice reduced")
G = Lred.gram_schmidt()[0] #Setting up CVP

# Finding an encoded message to forge using CVP
Found = False
counter = 0

while not Found: # Randomised CVP
    Found = True
    counter += 1
    w_targ = vector((257-w[i])/2 for i in range(40)) #In between 0 and 257-w
    rand_weights = [int(w_targ[i]//10) for i in range(40)] #Randomness depends on tightness of condition
    Y = w_targ + vector([rd.randint(-rand_weights[i],rand_weights[i]) for i in range(len(w))])
    k = Babai_NP(Lred,G,Y)
    if not all([int(a>=0) for a in k]):
        Found = False
    if not all([int((k[i]+w[i]) < 256) for i in range(40)]):
        Found = False
    if w+k == w:
        Found = False
print("Found k after" ,counter , "iterations:")
print(w+k)

w_prime = w+k 

# Revert the encoding to get m_forge

V = Matrix(GF(257),[[Support[i]**(j+1) for j in range(20)] for i in range(40)])
m_forge = V.solve_right(vector(GF(257),w_prime))
print("Forging signature for message", m_forge,'\n')

# Initiate server connection

from pwn import *

conn = remote("challenges.france-cybersecurity-challenge.fr","2153")
print('\n',conn.recvline(),'\n')
sign = conn.recvline().decode()
print(sign)
pk = conn.recvline().decode()
print(pk)

#Converting received elements

spl = sign[13:-2].split(',')
signed = []
for i in range(len(spl)):
    signed.append(spl[i][1+int(i!=0):-1])
signed = list(map(bytes.fromhex,signed))
spl = pk.split('[')
mask = bytes.fromhex(spl[0][7:-3])
spl = spl[1][:-3].split(',')
PK = [bytes.fromhex(spl[i][1+int(i!=0):-1]) for i in range(len(spl))]

# Computing the forgery from w_prime and Sign(m)

for i in range(40):
    for j in range(w[i]+1, w_prime[i] + 1):
        signed[i] = _H(signed[i], mask, i, j)

# Send forgery and terminate connection
        
print(conn.recvuntil(b'>>>'))
print(bytes(m_forge).hex(),'\n')
conn.send(str(bytes(m_forge).hex()).encode()+b"\n")
print(conn.recvuntil(b'>>>'))
conn.send(str([s.hex() for s in signed]).encode()+b"\n")
print(str([s.hex() for s in signed]),'\n')
print(conn.recvline())
print(conn.recvline(),'\n') # GET FLAG
conn.close()
```

This gives the following output:

```
Lattice initialised
Lattice reduced
Found k after 3 iterations:
(196, 127, 234, 194, 239, 247, 215, 160, 125, 238, 220, 196, 224, 220, 243, 220, 237, 247, 147, 242, 254, 144, 219, 251, 228, 242, 177, 247, 191, 241, 204, 206, 235, 155, 185, 238, 230, 161, 253, 132)
Forging signature for message (95, 89, 156, 61, 168, 46, 9, 91, 122, 30, 37, 135, 49, 55, 3, 29, 10, 167, 45, 87) 

[x] Opening connection to challenges.france-cybersecurity-challenge.fr on port 2153
[x] Opening connection to challenges.france-cybersecurity-challenge.fr on port 2153: Trying 54.36.209.75
[+] Opening connection to challenges.france-cybersecurity-challenge.fr on port 2153: Done

 b"message = b'WINTERNITZ IS COMING'\n" 

signature = ['fe72c1c5f11a279871491778f8531bfc4f57ccf2d835efdc689de1560e35b656', 'a55be558d92cfcaf12e58186fe37b328968dd81c907b74503b87f715ae94cec0', '968ad87ac6c950fce72b802f775625b77d1a9e33290bd5f7275f4d481c939d9d', '4b46627c2d185f66bfcd9170d4fc74ec09075cbb38890f79c7e120fe18652c9d', 'd4059171c94a28e6c357979f7439de6c0216d2ecb6ca863f8dbca5791c941be3', 'c8f70ef55ae64e26d425be14b300167b66ad1d13e5777f0a27793a30ab1e8af8', '3ce1566f43d1831ae93261b3fc1b11829094639d0499df801978d16f4d3826c8', '4d8dc4faa6d241e514f7097a1312381fbd1fcfa1916a61e678e3b9362494fc66', 'ec34e5844c9242b517e734bfff9304cfce44c58db02f62a4833772eede2f58a2', 'bdb6b91cb47d0ded3142f050d2587db7c4fcfff7e3c368f0d6b4d582b4a18709', '2f5178c8b7fd65f51222e8ba78b872015f0498442381de54c027f8e65bce777d', 'fbf0422dfbd7f1c7b5ab893fa51bd7525bc4542d92c8e898378ef3e46dbf05ee', 'da2173af6b08a3507e600bbee891aea6b579eec83bac6688922e53b399a83d48', 'e33390b6179a50484b0c06393c96090b631dd3398203ce43289f37b0c9fb4b7a', '537f2ff81c67cbe8a8fe11a59b758c8034e9d5049699eecb404421aacbc28fce', '00be127437ed42cff51784f658f45f4d4ae16e04d1ee8e6287d85c8461a5ed4f', '27fdc72f44a37efc3463c608fb6e3e1461908a95f619900bcd0deccf310b5217', 'e04f367ee23564cf8c4c5ebf38f76f040d29b0e4bd8efbbb7d01ddab5c3f0a60', 'f0b6e5fa21a24fde70638102540220f431dd8e6dad87ab6c393527526fd9fcf6', 'ca307832832c665be30dca7df98f8b7de31f4c34cba6126d30e56f26a560ac0b', '8eb2d3c796ec8eec2bdbf3401b874cf0143542ddf528aee049548a03660818a5', 'a9c446e9c9793f6bad079a35b0d8bb1453b9fa09211accde2530db8c07c4b82b', 'daf24c206835d463c9306c7419f7954d00f4a173b097fb06846b6447611169b6', '244b6115a6ef480c71006e5ec1f62d889905d9ee11d8a7ee57e6790208900225', '61d8f53220456059c293e4b1c7dc731e436cbf3863c0625deba52cb758318d00', '3df205faec24bb088dc11c295ab7b4cf384774e1d5b904013eee1af4ad1b238c', '46b74a87c433362ee7a41b42f4e892f53a48afce73af299c2a03897b8beacaf0', '6ad3176196c3866a102747be951cc30aff52ca0d7172842877fc609049640808', '3f7152fbdbf142d31ce18df0040352efbbd9763e94d433f0ec21bc1ed5fe7805', '4c04cf39d3a8a51eba91a83b5390a1f1b28b9b27c4d8ae1a2bb26ce351f36332', 'c92f716b73d0dd045c044e517a32ca8125c59a30827f8c10eb6a98dd30400930', '0b3acbdc88a04ba26a96f582bac1d57fc5d2bb51f5b93ac37874ee4bb62e9edc', 'c55829002ad179b8a04a4797309e88aaef7992ea8ea4402345be73c8fc934474', 'aaaace4dce8a77348a40090addbdcba984c43e4b203d7b545a8a4c53f3a23624', 'd1d5f9e31158b7c93a9fec601f24246105292100560f022d0a61c8debce7b131', '169cc801a03231c41767918ca6cf97bed6759f278bad5b49349f9c2426887bff', '1bba6a79699da5be3b35d1b276eb97aae06921c549871cc68bdc68e579d68b81', 'bb5efba86f29977a39ca8d474dbb9fb50f9e7435ce609c25c43c658d22d81c35', '4dbf40d50a0d6b28e8cb740154ae32926d7a5e643ca3fff2a22717f725c88e0d', 'bfc4f1eda5fa92756976053c8b597ed554c731f5c52d6774d07ab7dd6b616182']

pk = ('69343814c8a3a9f4af98d527972463e0', ['dd1d6eb2b2ffa5139ab350a0f1e3dd59d2db22d4cbff5779a6c962f690fe3c8f', '3a561dfd605306852fb79b6b507c022c41365968c7435c6429c91532435087b5', '44a40d865c3ccfcffa995741594f97ac69cbc7073e03b361160ca79ad02567a7', 'f5dbded1406c0626ea679b65e32488b9b94e41d30750992285c1cf3e946a4e9c', 'adefa1d330d9c3959aad7d6e66cf3d900b41a46d6f1dc576964fbd0c248661a0', 'aab045eef97718d23eec1184c8535f7fd7eb231606cf9da8389660463d3f463e', 'e1e046a2a99aefa05d109a0adfad49af7fa0b423c835cb44b4fe46704d5f0015', 'd3c5e7db22837c05e3f89ff4d5b79c6bc3c0f0f9b5141e9d19bb3f4e0c07834d', '55cbfd7b8f97bc8c5b9aec2ee0e0b19ecf8e4143851e57d2e35bbecf0c02c82f', 'c71bb9cb59474eea59731b84e05af60cb10f5bf2b82ac7f3df4d09a85b2728c8', '918dd4cce36aa5592852552f55a3a8b18dddb86bb778d294593b43b68f6cc5a2', 'a39da2fd76ef8582f3342fc90a7332d57cd39e45848ece1f952026b19a3d5ab5', '4d9b0cf760757bb8661e8244d8cfedca4d25b63aeecc9208816aab1029fe0a13', 'ea3d4fbf8c51f82bd175602f0d957ed17b9cc2cda8294d79e726957884a71aec', '45ec709a850fff737f5628f6a69046f6b079aea161bf1621a070b43319ce09c3', '13a5d9b89f62dc3c1473c5c33fa207cfc8f27b11d6584f57ff9dc6456d15570e', 'ddb627e349fc3512378bc9d1981ca43b536e3e5081b40b2d5262aa5adc283788', 'c61e913fac386ac6ce3054bce93f55ca33426678f0ca5359904a3a2d26a15ee4', '6b8fbe299e24c7bc7a6388e3263ca75f692a6f233e41f5865a1eec350ac4da6b', '345bff6e2f95dc5b69bd191dbe7551b9be6f194a915460e405fbab56f91eba21', '795663469da9cfd50c2fb0bf7a3c69a63561326a7de3779ebca5ba0a83e4fb02', 'fe9be9ede7f2a16640c7357acf71660d86fcdc1b851ff93c346bb773fb8be883', 'cafd05c22ee1d03420cd9f0507e08a1762afcf6b49321174b6a0803aa01157c1', '77fc404d7b1b15265a53a679f0f4d4186c26c1c044ea332392fb56d4562cc1d2', '7044947cb9e42fe31a1cc8d7aae87131c95b206ac4465e0f563a94264bed78e7', 'b4fba57b6661b9b062769c07b230fc60936886cbdf1123680dc8228920b7099e', 'e7a14645903abbeb40735da6f8dd831e5e1b0e1830ef79979af6a93e2196f82c', 'db0cded39c6cac8145683952d1b7a39daae433cbf8649bb1b548cfdde20eba68', 'fdcf0a9cd0bf301f0b28e355053b1f00b58feb6d3d8ab2c1dbcafb6ab4e478d2', '31aeeaf66af9b444c1800dcb4bd913926927f0616d0573a609622188371fba90', 'b2e15ed334261a33cb4048ca164a9d5b0410ac6378f4c1bf7715bd36d93a9a4a', '535dae1f7afd3c11bce824ebf1e47e7c73e3a338b0e69767b88e644d705f116b', 'f69564e1e0c7a9aab846ebd47c49a8427c5a97839523f94e48fc71855e1d7bd5', '16a3333d5ee751cacb51a667257ec201b49fdbe37ee74e5067f67fa2159cc0f8', '8734cf75ac04b9e9a532007f286787a2f3f6090b541defd5fd22bf891cfac80f', 'bcd71d19fe9e37312e9e6f897b8b7e80b707dde0355939d711eb6b61a408f389', '648b5722410b90fc9e58cb67ab774bcd3eefb45a05d1f61f59485e6435720621', '8a3351f57370c3f1b832d9a15b0b1bae235950b068f00aaf4f2b9a6ba28c47ee', '6de40f7a182674633331fb0e4156d75a81edda264f23b7319aa0624fd0f3033f', '214b82f16dba524ae9a9d048d161fb61208aab4b0e1e2d9a04dd15270034aa7e'])

b'Input your message (hex format):\n>>>'
5f599c3da82e095b7a1e25873137031d0aa72d57 

b' Input your signature (list of hex strings):\n>>>'
['45eb6ff5eb3e2b5cf6d017e7b24f33e871c04c7c1abc7ef577c51470dfa0ffa5', '1cb9e84bf3919562b7a6a4b0f577475d15b0da87fb40bd7fd1669b101071bc55', '4efa6f1a2badbe0f14ea76cc69b075c9a021b781a87f3fd21da36ef0f087d263', '0f540994199568cb37f19d5c66dd1b4d172a348f157a05b6a29124852242fb61', 'd4059171c94a28e6c357979f7439de6c0216d2ecb6ca863f8dbca5791c941be3', 'e4c7418dda7aed865dea2444f0031e672767bec744c9ae59db8721e1c592fd20', 'bcc4ab40bad0ffcb825752efa52e02b97bf644dca14fb06e18747e41e64a31fd', '76077390f46bf0497bacccec78b0d78f6c49b0fbd5824a3cd0ae78f829c13c7f', '37a36d6d2ba3a6f1af0a176f8aaf29bcd2e24a9b980e882910e56dfd0482b211', 'c9166ede207409de1f35841cef12fbf0caa4974b700e1c0621963de904aa3f27', '5e6b4a42b79d04771dff1db43ea00aa592a61bb4c1c25bcc02cda609bfa8dfb9', '713418c91319ad754870dd32ac618a543c31045acad850ca832d419ddc3c2294', '14d3cba21bd959c7fd9fdc1293e41f08b7d72f988cf6c46e8258a626c940d6f9', '1cc537955abb2a8320fc574a989af193ba86091b898a453d117208cfb55aebae', '4b657db18820217ea4b5ae109f1a713909d0c1fa9d6e20a525474bfbcf547c74', '8ec74c4c6fa99172b19eae1dfe0aba8b3a5cdd3a156b3e917e52e378bf4700de', 'db5336153e049b0398e3a4a8e88033aec46558d762b9e2ac5dd1092c15ac76eb', '0af92f747ea20817ab8cf8f6e4a434ecc0af515cf0a4e1e5a5f18dfa80173adf', '8391ebbeef864c6381bfb4b0d10903a04fa5d05e35784e52cd7cfb22ca4e82f3', '606b8975518308f8d79d0af11cf5727fe58e89c8748367ec5d498a9c658f7faf', '40b83e304714eb48eaadc11fdec980ff2804c5fef2b39f3cf0cf95ffdb4dde1a', '3431bf8f0a1027f72cd03cc960253b3e4d34f6d69960c3f2f87d0570e341d966', 'dbcd8babba1716516de4900e9a64f6ee7e0c2a208622654f7f991c5dc8c9d89d', '2bd7c7864d556fc06478de7e34dfea1fecc4d167109f5aec7c55b423c91ffa13', '481e808ed795ac8fb12abe85c09c84f2fb5f1e94b6cef8cc854d57c68541c503', 'f8721f6a92f6383675e74e8b2fb919101f1341fbd2de5f15b156f8e582d0ff8c', '4c4505f639e18afeb9961c0d968d47db51c6f9dc8b72aa6e4b782db5acbbbbce', '1545b62aea2140cd289c15860c696e48fba9f738708dc16406a8898e4756aec0', '51c163cae819c203b15abfc2fe82b9c5ab2bc80bdc05ffa3862c6744231b678d', '96650aff953bfb0f9c792aaebc9223a62b224d6170ec98517932c934ad6aa4bb', 'cf52e98d57654d8fa35f37294cb3dee3091ea559b92a18420a0a31480176b0a2', '0ebebe044d6ad274c05de3ef6cb8dbddb61f2d27b170ab671431e83661647c96', '3c13b86b7370fd40a48c9a4681c2fcc75e0eaf869621c8c6f3bea6a7da2bd835', 'fb5dbb4125171c498cb94f80dce6bb03e2a4dc71157ebd573e7e45e67579e86b', 'fa30c2f9f777ae3852fad70f4ff1def1489b4ecf66ee6ba5089053b25311c2d9', '37760db8edbc7bc6cca0fa7b0088e53ef4e02167efcf6127e95e96239a122f5b', '3a09ce428d10a435f3c9b1b86eac79d9d435bcc03f455612372c56b9b4624bc6', '685e2b98917c562d1fa7f24400b573e12a74ff4c52823bae59c998abad142fc2', 'dd70604d4faf70c1c04753ce43cddfedade6f091e02e919ece8741d49ad829d2', 'cffce2eeaefe186f7f7ea03ddb68aed4d9132c944bd2bd869569caa8c2f82aad'] 

b' Congratulations! Here is your flag:\n'
b'FCSC{e2987e3e48e51343df63218484d5e760faf5cf15c9f01a8649a483a91c31ce11}\n' 

[*] Closed connection to challenges.france-cybersecurity-challenge.fr port 2153
``` 

We get the flag. I would like to thank the organisers of the CTF for this very fun challenge! 
