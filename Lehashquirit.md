---
# Le hash qui rit

| Chal info | FCSC2023 |
| ------ | ----------- |
| Name | Le hash qui rit |
| Category   | Crypto |
| Difficulty | :star: :star: |
| Number of solves | >60 |
| Type | xor collisions on SHA256 |
| Writeup by | htmb |

This challenge asks for a set of at most $256$ messages. It gives us a $256$-bit target value $v$ and requires that the xor of all SHA256 hashes of messages in our set is equal to this value.

Let $F_2$ denote the finite field with $2$ elements.

Let $V\in F_2^{256}$ be our target vector in binary. We generate $256$ arbitrary messages (for example randomly, but you can also have fun with message selection). Call them $m_1,\ldots,m_{256}$.

We then create a matrix $H\in F_2^{256\times256}$ whose $i$-th column corresponds to the SHA256 hash of $m_i$. 

If $H$ is not invertible, select new random messages (this happens with probability $1/2$ as the determinant of $H$ is $0$ or $1$ with equal probability).

Once $H$ is indeed invertible, we compute $X=H^{-1}V$ (this is very fast, especially over $F_2$).

We now have $|X|\le 256$ and $$\bigoplus_{X_i=1}\text{SHA256}(m_i)=v.$$

This gives us a solution (by the way the matrix is invertible so our set contains exactly $|X|$ messages). Note that by elementary probability theory we expect a list of size 128 on average, which is much better than 256 anyways.

We write the following script in sage (reusing some code from the challenge):

```py
import hashlib, os

def bit_from_bytes(h, idx):
    return (int.from_bytes(h, byteorder='big') >> idx) & 1

def xor_binary_string(b1, b2):
    size = max(len(b1),len(b2))
    result = bytearray(b'\x00'*size)
    for i in range(size):
        result[i] = b1[i] ^^ b2[i]
    return bytes(result)

def hashs(value): #SHA256
    if not isinstance(value, bytes):
        raise TypeError('Value for hash must be in bytes')
    m = hashlib.sha256()
    m.update(value)
    hashval = m.digest()
    return hashval

def xor_hash(liste): #xoring hashes of a list of messages
    result = b'\x00'*32
    for plaintext in liste:
        result = xor_binary_string(result, hashs(plaintext))
    return result

K = GF(2) #finite field F2

target = bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") #target value
v = vector([K(bit_from_bytes(target,i)) for i in range(256)]) #target bits

is_invertible = False

while not is_invertible:

    hashes = []
    messages = []

    for i in range(256): #generate 256 random messages
        messages.append(os.urandom(8)) #the 8 is not important, just pick anything thats not tiny
        hashes.append(hashs(messages[-1]))

    tab = []
    for i in range(256):
        line = []
        for j in range(256):
            line.append(K(bit_from_bytes(hashes[i],j)))
        tab.append(line)
    
    H = Matrix(K,256,256,tab)
    if(H.rank() == 256): #check that H is nonsingular
        is_invertible = True
        x = v*H.inverse()
        res = []
        for i in range(256):
            if(x[i]):
                res.append(messages[i])
                
assert xor_hash(res) == target #check result

print(len(res))
for m in res:
    print(m.hex())
```

Don't forget to write a small script using pwntools or telnetlib, otherwise you have to manually copy all $128$ strings.

We then obtain the flag: `FCSC{935b4fd518457e2f5099e0818fbc4a71417f46f9068c9c6eca304e662cf0cb5c}`.
