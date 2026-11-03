# BlindAgent: Hackathon Video Demonstration Script

This document provides a 3-minute video presentation and screen-recording script for your submission to the **Mathematics for Systems Security Hackathon (AI Pipeline Secret Sharing Track)**.

---

## Video Outline & Timestamps (Target: 2 to 3 minutes)

| Timestamp | Section | Visual on Screen |
| :--- | :--- | :--- |
| **0:00 - 0:35** | **The Problem & Threat Model** | Slides / Diagram showing prompt leakage in Cloud LLMs (Gemini, OpenAI). |
| **0:35 - 1:15** | **Low-Level Mathematical Architecture** | Terminal showing `make test` (C engine verification of $GF(2^8)$ and SSS). |
| **1:15 - 2:00** | **Live Terminal TUI Demonstration** | Interactive `python3 ui/tui.py` showing split-screen (Enclave vs Cloud Wire). |
| **2:00 - 2:40** | **Loopback Web Dashboard (`localhost:8000`)** | Browser view of the GUI, real-time SSS polynomial share generator & reconstructor. |
| **2:40 - 3:00** | **Conclusion & Security Guarantee** | Recap of zero-leakage, information-theoretic secrecy, and constant-time safety. |

---

## Step-by-Step Recording Guide

### Scene 1: The Problem (0:00 - 0:35)
**Voiceover:**
> *"When developers send prompts containing API keys, passwords, or SSNs to cloud LLM providers like Gemini or OpenAI, those secrets are logged and stored in third-party servers. If the provider is compromised or an insider inspects the logs, your master key is leaked.*
> *We built **BlindAgent**—a zero-leakage AI pipeline that mathematically blinds sensitive inputs and splits secrets using Shamir's Secret Sharing over Galois Field $GF(2^8)$ before any data leaves your machine. The cloud agent reasons over blinded tokens, while the master key never leaves your local enclave."*

---

### Scene 2: The Low-Level Cryptographic Core (0:35 - 1:15)
**Action:**
Open your terminal in the `blindagent` directory and execute:
```bash
make clean && make test
```
**Voiceover:**
> *"To ensure low-level execution and side-channel immunity, our cryptographic engine is written in native C with branchless constant-time arithmetic. Here we run our automated verification suite:*
> *First, it validates the field axioms of Galois Field $GF(2^8)$ modulo the irreducible polynomial $P(x) = x^8 + x^4 + x^3 + x + 1$.*
> *Second, it tests our constant-time multiplicative inverse via Fermat's Little Theorem ($a^{254}$).*
> *Third, it splits a master secret into a $(3, 5)$ Shamir threshold scheme, proving exact recovery using Lagrange interpolation."*

---

### Scene 3: The Terminal User Interface (TUI) (1:15 - 2:00)
**Action:**
Run the interactive TUI:
```bash
PYTHONPATH=. python3 ui/tui.py
```
Type `1` to select Preset 1:
```
Please generate an SQL audit query for employee SSN: 123-45-6789 and master_key: SuperSecretMasterPassword! with balance $50,000.
```
*(Or type `3` to demonstrate wrapping arbitrary confidential text in `<secret>ProjectTitanium-AccessCode-900</secret>`)*

**Voiceover:**
> *"Notice the dual-pane inspector:*
> *On the left is our Local Client Enclave. We see the original plaintext prompt and the final decrypted SQL query.*
> *On the right is what the cloud host provider actually receives over the wire. Notice that the SSN, master key, and financial balance are replaced with blinded algebraic tokens. Furthermore, the master key is decomposed into $GF(2^8)$ polynomial shares.*
> *Users can also wrap ANY custom secret with `<secret>...</secret>` tags for instant zero-knowledge protection.*
> *Even if the cloud provider logs every single byte of this request, they have zero mathematical knowledge of the master key!"*

---

### Scene 4: The Loopback Web Dashboard (2:00 - 2:40)
**Action:**
1. Start the web server:
   ```bash
   PYTHONPATH=. python3 ui/server.py
   ```
2. Open your browser to: `http://127.0.0.1:8000`
3. Click **"Execute Zero-Leakage Pipeline"** to show the live split view.
4. Click on the **"Galois Field SSS Lab"** tab.
5. Enter a secret key, click **"Generate"**, then uncheck 3 shares (leaving only 2 of 3) and click **"Reconstruct"** to demonstrate that $< k$ shares cannot reconstruct. Check 3 shares and reconstruct successfully!

**Voiceover:**
> *"We also built a web dashboard hosted locally on loopback. Here, users can test prompts and inspect our Galois Field SSS Lab.*
> *We can adjust the threshold $k$ and total shares $n$. Selecting any 3 of the 5 shares reconstructs our key in under 1 millisecond. But selecting fewer than $k$ shares guarantees Shannon information-theoretic secrecy: $\mathcal{I}(S; \text{Shares}_{k-1}) = 0$."*

---

### Scene 5: Conclusion (2:40 - 3:00)
**Voiceover:**
> *"BlindAgent bridges advanced finite field mathematics and modern AI pipelines—guaranteeing that developers can leverage state-of-the-art LLMs with zero privacy compromises and zero master key exposure.*
> *Thank you!"*
