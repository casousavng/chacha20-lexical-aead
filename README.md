# ChaCha20-Poly1305 Lexical AEAD (Pure Python, RFC 8439)

Reference artifact for the paper:

> **Hardware-Agnostic Lexical AEAD Codebook Concealment via Pure-Python ChaCha20-Poly1305: Canonical Framing, Avalanche Dynamics, and Heuristic DPI Evasion**  
> Carlos André Sousa — Master in Cybersecurity and Computer Systems Auditing (MARSI), ISPGAYA

## Overview

A zero-third-party-dependency Python 3 implementation of **Lexical Authenticated Encryption with Associated Data (AEAD)** grounded in **IETF RFC 8439 (ChaCha20-Poly1305)**:

- **Decoupled Benign Cover Lexicon (`N = 256`):** Maps sensitive operational commands onto a disjoint 256-word everyday benign cover vocabulary over $\mathbb{Z}_{256}$ ($b = 8 \mid \gcd(96, 128, 16)$), eliminating modulo truncation bias ($\Delta p = 0$), non-canonical encoding malleability, MSB-token distinguishers, and operational keyword leakage simultaneously.
- **Strict RFC 8439 Parity:** 100% bit-for-bit verified against all 64 output bytes of Section 2.3.2 (ChaCha20), Section 2.5.2 (Poly1305), and all 114 ciphertext bytes + 16 tag bytes of Section 2.8.2 (AEAD with AAD).
- **Canonical Anti-Malleability & CSPRNG Framing:** Enforces strict upper-bound checks ($V < 2^{96}$, $T < 2^{128}$) for arbitrary $N$ (including legacy $N = 20$), CSPRNG 96-bit nonces via `os.urandom(12)`, constant-time tag comparison, and authenticated randomized bucket padding (`pad_bucket`).
- **Baseline Comparison:** Includes a head-to-head implementation of standard RFC 8439 AEAD + Base-256 cover encoding, demonstrating up to **82.0% smaller wire payloads** ($586.9\text{ B}$ vs. $3{,}256.2\text{ B}$) and **$2.9\times$ higher token throughput** on extended operational reports.

## Repository Structure

```text
.
├── executar_artefacto.sh                    # One-command full reproducibility pipeline
├── codigo_python/
│   ├── poly1305.py                          # Pure-Python RFC 8439 Poly1305 + AAD framing
│   ├── app.py                               # ChaCha20 core, LexicalAEAD (N=256 & N=20), padding & unit proofs
│   ├── benchmark.py                         # SAC, entropy, Chi-Square, MSB audit, R=30 throughput suite
│   ├── experimento_pratico_dpi.py           # Two-regime stateless heuristic DPI & 1,000-trial tamper suite
│   ├── resultado_benchmark.json             # Reference benchmark output
│   └── resultado_experimento_dpi.json       # Reference DPI & tamper output
├── LICENSE                                  # MIT License
└── README.md
```

## Quick Start & Reproducibility

Requires only **Python 3.10+** (zero external packages):

```bash
bash executar_artefacto.sh
```

The script executes all three validation phases and prints a dynamic summary directly from the freshly generated JSON reports:

1. **Phase 1 (`codigo_python/app.py`):** RFC 8439 official test vectors (Sections 2.3.2, 2.5.2, 2.8.2), decoupled `N=256` cover lexicon, AAD integrity, non-canonical overflow rejection (`+2^96`, `+2^128`, OOV), bucket padding (`B=64`), and RFC 8439 + Base-256 baseline comparison.
2. **Phase 2 (`codigo_python/benchmark.py`):** Strict Avalanche Criterion ($n=300$, exact $t$/$p$-values), skewed-plaintext dispersion ($m=5{,}000$), vocabulary scaling ($N \in \{16, 20, 64, 128, 256\}$), MSB-token distinguisher audit ($2{,}000$ packets), and multi-trial throughput ($R=30$ repetitions, mean $\pm$ std).
3. **Phase 3 (`codigo_python/experimento_pratico_dpi.py`):** 10,000-packet stateless heuristic DPI simulation across short (6-word) and extended (60-word) payload regimes (byte entropy, ASCII printability, and keyword-watchlist rules) plus 1,000 four-vector tampering trials.

## License

Released under the [MIT License](LICENSE).
