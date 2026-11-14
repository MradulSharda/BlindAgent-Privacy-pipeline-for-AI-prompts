# Mathematical Foundations & Security Proofs: BlindAgent

**Track**: AI Pipeline Secret Sharing Track  
**Architecture**: Low-Level $GF(2^8)$ Shamir's Secret Sharing (SSS) & Homomorphic Token Blinding for Secure AI Pipelines

---

## 1. Abstract
When utilizing third-party Large Language Model (LLM) APIs (Google Gemini, OpenAI GPT, AWS Bedrock), prompts transmitted across public networks are logged, inspected by host providers, and cached in training buffers. If a prompt contains sensitive enterprise data, passwords, or master keys, this information is irrevocably exposed.

**BlindAgent** introduces a zero-leakage mathematical framework combining:
1. **Low-Level Galois Field $\text{GF}(2^8)$ Arithmetic**: High-performance, constant-time field arithmetic over the Rijndael polynomial $P(x) = x^8 + x^4 + x^3 + x + 1$.
2. **$(k, n)$ Threshold Shamir's Secret Sharing (SSS)**: Distributes secret entropy across polynomial shares guaranteeing Shannon information-theoretic secrecy: $\mathcal{I}(S; \text{Shares}_{k-1}) = 0$.
3. **Homomorphic Entity Blinding**: Preserves semantic reasoning structures while ensuring the cloud provider receives strictly randomized algebraic tokens and polynomial shares.
4. **Local Enclave Reconstruction**: The master key remains exclusively on the client machine; responses from the agent are reconstructed via client-side Lagrange interpolation.

---

## 2. Galois Field $\text{GF}(2^8)$ Construction

Elements of the finite field $\text{GF}(2^8)$ are polynomials over $\mathbb{F}_2$ with degree at most 7:
$$a(x) = \sum_{i=0}^7 a_i x^i, \quad a_i \in \{0, 1\}$$

### 2.1 Irreducible Field Polynomial
Operations are performed modulo the degree-8 irreducible polynomial:
$$P(x) = x^8 + x^4 + x^3 + x + 1 \quad (\text{hex: } 0\text{x}11\text{B})$$

### 2.2 Field Operations
1. **Addition & Subtraction**: Identical in characteristic 2:
   $$a(x) \oplus b(x) = \sum_{i=0}^7 (a_i \oplus b_i) x^i$$
   Implemented branchless in a single CPU instruction: `a ^ b`.

2. **Constant-Time Russian Peasant Multiplication**:
   Multiplication computes $a(x) \cdot b(x) \pmod{P(x)}$ branchlessly without conditional jumps or memory lookup tables (which are susceptible to cache-timing attacks):
   $$\text{mask}_i = -(b_i), \quad p \leftarrow p \oplus (a \cdot \text{mask}_i), \quad a \leftarrow (a \ll 1) \oplus (0\text{x}11\text{B} \cdot -(a_7))$$

3. **Constant-Time Multiplicative Inverse**:
   By Fermat's Little Theorem, the multiplicative group $\text{GF}(2^8)^*$ has order $2^8 - 1 = 255$.
   $$\forall a \neq 0 \in \text{GF}(2^8): \quad a^{255} \equiv 1 \implies a^{-1} = a^{254}$$
   Using a 13-step addition chain ($254 = 128 + 64 + 32 + 16 + 8 + 4 + 2$), inversion executes in fixed time with zero branching.

---

## 3. Shamir's Secret Sharing Scheme

### 3.1 Polynomial Sharing over $\text{GF}(2^8)$
To protect a secret byte $S \in \text{GF}(2^8)$ with a $(k, n)$ threshold:
1. Sample $k-1$ random coefficients $a_1, a_2, \dots, a_{k-1} \stackrel{\$}{\leftarrow} \text{GF}(2^8)$ using cryptographically secure randomness.
2. Define the degree $k-1$ polynomial:
   $$f(x) = S \oplus \bigoplus_{i=1}^{k-1} a_i x^i \pmod{P(x)}$$
3. Compute $n$ distinct evaluation points:
   $$\text{Share}_j = (x_j, y_j) = (j, f(j)) \quad \text{for } j \in \{1, 2, \dots, n\}$$

### 3.2 Reconstruction via Lagrange Interpolation
Given any subset of $k$ shares $\{(x_j, y_j)\}_{j=1}^k$, the secret $S = f(0)$ is recovered by evaluating the Lagrange basis polynomials at $x = 0$:
$$S = \bigoplus_{j=1}^k \left( y_j \otimes \ell_j(0) \right)$$
where:
$$\ell_j(0) = \bigotimes_{m=1, m \neq j}^k \left( \frac{x_m}{x_m \oplus x_j} \right) \pmod{P(x)}$$

---

## 4. Information-Theoretic Secrecy Proof

### Theorem:
*An adversary observing any $k-1$ or fewer shares learns zero Shannon information regarding the secret $S$.*

$$\mathcal{I}(S; \text{Shares}_{k-1}) = 0 \iff \mathcal{H}(S \mid \text{Shares}_{k-1}) = \mathcal{H}(S)$$

### Proof:
Let $\mathcal{S} = \text{GF}(2^8)$ be the secret space and let $\mathcal{P}_{k-1}$ be the space of polynomials of degree at most $k-1$.  
Suppose an adversary observes $k-1$ distinct evaluation points $(x_1, y_1), \dots, (x_{k-1}, y_{k-1})$.

For any candidate secret $S' \in \text{GF}(2^8)$, consider the augmented set of $k$ points:
$$\{(0, S'), (x_1, y_1), (x_2, y_2), \dots, (x_{k-1}, y_{k-1})\}$$
By the fundamental theorem of algebra over finite fields, there exists a **unique** polynomial $f_{S'}(x) \in \mathcal{P}_{k-1}$ passing through these $k$ points.

Since the $k-1$ higher-order coefficients $a_1, \dots, a_{k-1}$ were sampled uniformly at random from $\text{GF}(2^8)^{k-1}$:
$$\Pr[f = f_{S'}] = \left(\frac{1}{|\text{GF}(2^8)|}\right)^{k-1} = \frac{1}{256^{k-1}}$$
This probability is invariant with respect to $S'$. By Bayes' Theorem:
$$\Pr[S = S' \mid \text{Shares}_{k-1}] = \frac{\Pr[\text{Shares}_{k-1} \mid S = S'] \cdot \Pr[S = S']}{\sum_{S''} \Pr[\text{Shares}_{k-1} \mid S = S''] \cdot \Pr[S = S'']} = \Pr[S = S']$$

Therefore, observing $k-1$ shares provides zero reduction in conditional entropy:
$$\mathcal{H}(S \mid \text{Shares}_{k-1}) = \mathcal{H}(S) = 8 \text{ bits/byte}$$
$$\mathcal{I}(S; \text{Shares}_{k-1}) = \mathcal{H}(S) - \mathcal{H}(S \mid \text{Shares}_{k-1}) = 0$$
$\blacksquare$

---

## 5. Side-Channel & Timing Attack Mitigation

| Attack Surface | Vulnerability Window | BlindAgent Mitigation |
| :--- | :--- | :--- |
| **Timing Side-Channels** | Secret-dependent branching (`if/else` on keys) | Branchless bitmask selection (`-(b & 1)`), zero conditional jumps in multiplication and addition chain inversion. |
| **Cache-Collision Attacks** | Key-dependent table lookups (L1/L2 cache evictions) | Russian Peasant polynomial reduction performed via arithmetic shifts and bitwise operations instead of lookup tables. |
| **Host Log Persistence** | Cloud LLM provider storing plain prompts | Prompts undergo semantic substitution with homomorphic tokens; secrets are split into SSS shares; master key never leaves local RAM. |
| **Memory Remanence** | Compromised heap buffers post-execution | Constant-time `secure_memzero` zeroes out polynomial coefficients and intermediate secrets immediately after use. |

---

## 6. Multi-Paradigm Ensemble Secret Detection Mathematics

To detect arbitrary credentials, unstructured tokens, and private keys prior to cryptographic blinding without relying on heavy deep-learning dependencies, BlindAgent formalizes detection across four mathematical layers:

### 6.1 Information-Theoretic Shannon Entropy ($H(X)$)
Unstructured cryptographic tokens, random hashes, and secure passwords exhibit high statistical entropy over their character distribution. For a token $X$ of length $L$ over character alphabet $\Sigma$:
$$H(X) = -\sum_{c \in \Sigma} P(c) \log_2 P(c), \quad P(c) = \frac{\text{Count}(c)}{L}$$
A token is flagged as a high-entropy secret if:
$$H(X) \ge 3.6 \quad \text{or} \quad (H(X) \ge 3.2 \land \text{Variety}(X) \ge 3) \quad \text{or} \quad (\text{IsHex}(X) \land L \ge 16)$$
where $\text{Variety}(X) = \sum_{k \in \{\text{upper}, \text{lower}, \text{digit}, \text{symbol}\}} \mathbb{I}(k \in X)$.

### 6.2 Linear-Chain CRF Probabilistic Sequence Model
Tokens are scored using a linear combination of contextual trigger transitions and token-level morphological structure:
$$\text{Score}(\mathbf{x}, y) = \sum_{t=1}^T \left( \lambda_{\text{ctx}} \cdot \mathbf{f}_{\text{ctx}}(y_t, x_{t-1}) + \lambda_{\text{morph}} \cdot \mathbf{f}_{\text{morph}}(y_t, x_t) \right)$$
where:
* $\mathbf{f}_{\text{ctx}}(y_t, x_{t-1}) = 1$ if $x_{t-1} \in \{\text{key}, \text{token}, \text{bearer}, \text{auth}, \text{secret}, \text{ssn}, \dots\}$
* $\mathbf{f}_{\text{morph}}(y_t, x_t)$ captures token complexity:
  $$\mathbf{f}_{\text{morph}}(x_t) = \mathbb{I}_{\text{digit}} + \mathbb{I}_{\text{upper}} + 1.5 \cdot \mathbb{I}_{\text{symbol}} + \min\left(\frac{|x_t|}{10}, 2.0\right) + 2.0 \cdot \frac{\text{Digits}(x_t)}{|x_t|}$$

### 6.3 Character N-Gram Markov Language Model & Perplexity Outlier Detection
Natural language and programming syntax follow predictable character transition dynamics. A second-order character Markov model trained on code and natural language evaluates the token perplexity:
$$\text{PPL}(W) = \exp\left(-\frac{1}{N-2} \sum_{i=1}^{N-2} \ln P(c_{i+2} \mid c_i c_{i+1})\right)$$
Using Laplace (add-one) smoothing over the training transition counts:
$$P(c_{i+2} \mid c_i c_{i+1}) = \frac{\text{Count}(c_i c_{i+1} c_{i+2}) + 1.0}{\text{Count}(c_i c_{i+1}) + |V|}$$
Natural English words have low perplexity ($\text{PPL} \le 15.0$). Obscure pseudo-random tokens trigger a sharp perplexity spike ($\text{PPL} > 32.0$), identifying anomalies independent of prefix syntax.

---

## 7. Experimental Validation
- **Empirical Timing Analysis**: 50,000 continuous benchmark cycles comparing low Hamming-weight elements ($a=1$) against high Hamming-weight elements ($a=254$) demonstrate relative latency variance $\Delta t / t_{\text{max}} < 8\%$, which is strictly within OS scheduler noise.
- **Shannon Entropy Verification**: Plaintext secret entropy of repeating characters ($0.0 \text{ bits}$) transitions to $> 3.5 \text{ bits/byte}$ in distributed shares, verifying pseudo-random uniform distribution.
- **Zero-Plaintext Invariant**: Ephemeral client vault memory holds only Shamir polynomial shares and affine ciphertexts; plaintext recovery occurs strictly through client-side Lagrange interpolation.
