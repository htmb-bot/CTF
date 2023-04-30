---
# Le hash qui rit

| Chal info | FCSC2023 |
| ------ | ----------- |
| Name | Le hash qui rit |
| Category   | Crypto |
| Difficulty | :star: :star: |
| Number of solves | $>$50 |
| Type | xor collisions on SHA256 |
| Writeup by | htmb |

This challenge asks for a non-empty set of at most $256$ messages. It gives us a 256-bit target value $v$ and requires that the xor of all SHA256 hashes of messages in our set is equal to this value.

Let $V\in\F_2^{256}$ be our target vector in binary. We generate $256$ arbitrary messages (for example randomly, but you can also have fun with message selection). Call them $m_1,\ldots, m_{266}$.

We then create a matrix $H\in\F_2^{256\times256}$ whose $i$-th column corresponds to the SHA256 hash of $m_i$. 

If $H$ is not invertible, select new random messages (this happens with probability $1/2$ as the determinant of $H$ is $0$ or $1$ with equal probability).

Once $H$ is indeed invertible, we calculate $X=H^{-1}V$ (this is super fast, especially over $F_2$).

We now have $|X|\le 256$ and $\bigoplus_{X_i=1}\text{SHA256}(m_i)=v$.
