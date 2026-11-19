# ==============================================================================
# BENCHMARK, COMPARATIVO E TESTES ESTATÍSTICOS (TP2 CRIPTOGRAFIA APLICADA)
# PYTHON PURO (ZERO LIBS EXTERNAS - APENAS STDLIB: math, time, random, json, pathlib)
# ==============================================================================
import json
import math
import random
import time
from pathlib import Path

from app import (
    VOCABULARIO,
    VOCABULARIO_COBERTURA_256,
    N,
    PALAVRA_PARA_ID,
    ID_PARA_PALAVRA,
    MOTOR_OPTIMO_256,
    MOTOR_TATICO_20,
    chacha20_block,
    normalizar_chave_256bits,
    validar_vetor_rfc8439,
    validar_vetor_aead_rfc8439_secao282,
    derivar_deslocamentos_chacha20,
    cifrar_com_chacha20,
    cifrar_aead_lexical,
    cifrar_rfc8439_base256,
)
from poly1305 import validar_vetor_poly1305_rfc8439


# ------------------------------------------------------------------------------
# FUNÇÕES ESTATÍSTICAS EXATAS EM PYTHON PURO (ZERO SCIPY)
# ------------------------------------------------------------------------------

def _gamma_p_series(a: float, x: float) -> float:
    """Série de potência para função gama incompleta regularizada inferior P(a, x)."""
    if x <= 0.0:
        return 0.0
    gln = math.lgamma(a)
    ap = a
    summ = 1.0 / a
    delta = summ
    for _ in range(1, 500):
        ap += 1.0
        delta *= x / ap
        summ += delta
        if abs(delta) < abs(summ) * 1e-14:
            break
    return summ * math.exp(-x + a * math.log(x) - gln)


def _gamma_q_cf(a: float, x: float) -> float:
    """Fração contínua de Lentz para função gama incompleta regularizada superior Q(a, x)."""
    gln = math.lgamma(a)
    fpmin = 1e-300
    b = x + 1.0 - a
    c = 1.0 / fpmin
    d = 1.0 / b
    h = d
    for i in range(1, 500):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < fpmin:
            d = fpmin
        c = b + an / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-14:
            break
    return math.exp(-x + a * math.log(x) - gln) * h


def chi2_p_value(chi_sq: float, df: int) -> float:
    """Calcula p-value exato P(X >= chi_sq) para distribuição Chi-Quadrado com df graus de liberdade."""
    if chi_sq <= 0.0:
        return 1.0
    a = df / 2.0
    x = chi_sq / 2.0
    if x < a + 1.0:
        return max(0.0, 1.0 - _gamma_p_series(a, x))
    return max(0.0, _gamma_q_cf(a, x))


def student_t_two_tailed_p(t_stat: float, df: int) -> float:
    """
    Calcula p-value bilateral exato para teste t de Student via quadratura de Simpson
    sobre a densidade de Student-t (para df=299, precisão > 10^-12).
    """
    t_abs = abs(t_stat)
    if t_abs == 0.0:
        return 1.0
    # PDF de Student-t: c * (1 + u^2 / df)^(-(df+1)/2)
    log_c = math.lgamma((df + 1) / 2.0) - math.lgamma(df / 2.0) - 0.5 * math.log(df * math.pi)
    c = math.exp(log_c)

    def pdf(u: float) -> float:
        return c * ((1.0 + (u * u) / df) ** (-0.5 * (df + 1)))

    # Integra de 0 até t_abs via Simpson composto (1000 subintervalos)
    steps = 1000
    h = t_abs / steps
    s = pdf(0.0) + pdf(t_abs)
    for k in range(1, steps):
        s += (4.0 if k % 2 == 1 else 2.0) * pdf(k * h)
    cdf_half = (h / 3.0) * s
    return max(0.0, 1.0 - 2.0 * cdf_half)


# ------------------------------------------------------------------------------
# CIFRAS COMPARATIVAS IMPLEMENTADAS EM PYTHON PURO
# ------------------------------------------------------------------------------

def cifra_substituicao_estatica(tokens: list[str], mapa_permutacao: dict[str, str]) -> list[str]:
    """Cifra de substituição monoalfabética / codebook estático clássico."""
    return [mapa_permutacao[t] for t in tokens]


def cifra_vigenere_codebook(tokens: list[str], chave_ids: list[int]) -> list[str]:
    """Cifra polialfabética estilo Vigenère aplicada ao vocabulário modular N."""
    k_len = len(chave_ids)
    return [
        ID_PARA_PALAVRA[(PALAVRA_PARA_ID[token] + chave_ids[i % k_len]) % N]
        for i, token in enumerate(tokens)
    ]


class RC4Stream:
    """Implementação pura do stream cipher RC4 (KSA + PRGA) para comparação."""
    def __init__(self, key: list[int]):
        self.S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + self.S[i] + key[i % len(key)]) & 0xFF
            self.S[i], self.S[j] = self.S[j], self.S[i]
        self.i = 0
        self.j = 0

    def next_byte(self) -> int:
        self.i = (self.i + 1) & 0xFF
        self.j = (self.j + self.S[self.i]) & 0xFF
        self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
        return self.S[(self.S[self.i] + self.S[self.j]) & 0xFF]


def cifra_rc4_codebook(tokens: list[str], key_bytes: list[int]) -> list[str]:
    """Cifra de fluxo RC4 aplicada sobre o vocabulário N."""
    rc4 = RC4Stream(key_bytes)
    cifrado = []
    for token in tokens:
        b1 = rc4.next_byte()
        b2 = rc4.next_byte()
        shift = ((b1 << 8) | b2) % N
        c_id = (PALAVRA_PARA_ID[token] + shift) % N
        cifrado.append(ID_PARA_PALAVRA[c_id])
    return cifrado


def cifra_chacha20_stream_tokens(tokens: list[str], key_bytes: list[int], nonce_bytes: list[int], modulo: int = 256) -> list[str]:
    """Cifra modular direta sobre tokens pré-tokenizados (comparação justa sem parsing repetido)."""
    deslocamentos = derivar_deslocamentos_chacha20(key_bytes, nonce_bytes, len(tokens), modulo, rejection_sampling=True)
    if modulo == 256:
        op_map = MOTOR_OPTIMO_256.op_para_id
        cob_map = MOTOR_OPTIMO_256.id_para_cob
        return [cob_map[(op_map[t] + deslocamentos[i]) % 256] for i, t in enumerate(tokens)]
    return [ID_PARA_PALAVRA[(PALAVRA_PARA_ID[t] + deslocamentos[i]) % N] for i, t in enumerate(tokens)]


# ------------------------------------------------------------------------------
# MÉTRICAS ESTATÍSTICAS
# ------------------------------------------------------------------------------

def calcular_entropia_shannon(tokens: list[str]) -> float:
    """Calcula entropia empírica de Shannon em bits por símbolo."""
    if not tokens:
        return 0.0
    contagens: dict[str, int] = {}
    for t in tokens:
        contagens[t] = contagens.get(t, 0) + 1
    total = len(tokens)
    return -sum((c / total) * math.log2(c / total) for c in contagens.values())


def teste_qui_quadrado(tokens: list[str], tamanho_vocab: int, mapa_id: dict[str, int] | None = None) -> tuple[float, float, float]:
    """Retorna (chi_sq, esperado, p_value) sob hipótese nula de uniformidade em Z_N."""
    total = len(tokens)
    if total == 0:
        return 0.0, 0.0, 1.0
    mapa = PALAVRA_PARA_ID if mapa_id is None else mapa_id
    esperado = total / tamanho_vocab
    contagens = [0] * tamanho_vocab
    for t in tokens:
        contagens[mapa[t]] += 1
    chi_sq = sum(((obs - esperado) ** 2) / esperado for obs in contagens)
    p_val = chi2_p_value(chi_sq, tamanho_vocab - 1)
    return chi_sq, esperado, p_val


def teste_autocorrelacao_serial(tokens: list[str], lag: int = 1, mapa_id: dict[str, int] | None = None) -> float:
    """Calcula coeficiente de autocorrelação serial r_k (lag k) sobre índices modulares."""
    m = len(tokens)
    if m <= lag:
        return 0.0
    mapa = PALAVRA_PARA_ID if mapa_id is None else mapa_id
    indices = [mapa[t] for t in tokens]
    media = sum(indices) / m
    numerador = sum((indices[i] - media) * (indices[i + lag] - media) for i in range(m - lag))
    denominador = sum((x - media) ** 2 for x in indices)
    return 0.0 if denominador == 0 else numerador / denominador


# ------------------------------------------------------------------------------
# 1. STRICT AVALANCHE CRITERION (SAC)
# ------------------------------------------------------------------------------

def teste_avalanche_chacha20(iteracoes: int = 300) -> dict[str, float]:
    amostras_bits = []
    total_bits_bloco = 512
    nonce = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    random.seed(42)
    for _ in range(iteracoes):
        chave_base = [random.randint(0, 255) for _ in range(32)]
        bloco_base = chacha20_block(chave_base, 1, nonce)
        byte_flip = random.randint(0, 31)
        bit_flip = random.randint(0, 7)
        chave_mod = list(chave_base)
        chave_mod[byte_flip] ^= (1 << bit_flip)
        bloco_mod = chacha20_block(chave_mod, 1, nonce)
        diff_bits = sum((b1 ^ b2).bit_count() for b1, b2 in zip(bloco_base, bloco_mod))
        amostras_bits.append(diff_bits)

    media_bits = sum(amostras_bits) / iteracoes
    desvio_padrao = math.sqrt(sum((x - media_bits) ** 2 for x in amostras_bits) / (iteracoes - 1))
    t_stat = (media_bits - 256.0) / (desvio_padrao / math.sqrt(iteracoes))
    p_val = student_t_two_tailed_p(t_stat, iteracoes - 1)
    return {
        "media_bits": media_bits,
        "desvio_padrao": desvio_padrao,
        "percentual": (media_bits / total_bits_bloco) * 100.0,
        "t_stat": t_stat,
        "p_value": p_val,
    }


def teste_avalanche_nonce_chacha20(iteracoes: int = 300) -> dict[str, float]:
    amostras_bits = []
    total_bits_bloco = 512
    random.seed(84)
    chave = [random.randint(0, 255) for _ in range(32)]
    for _ in range(iteracoes):
        nonce_base = [random.randint(0, 255) for _ in range(12)]
        bloco_base = chacha20_block(chave, 1, nonce_base)
        byte_flip = random.randint(0, 11)
        bit_flip = random.randint(0, 7)
        nonce_mod = list(nonce_base)
        nonce_mod[byte_flip] ^= (1 << bit_flip)
        bloco_mod = chacha20_block(chave, 1, nonce_mod)
        diff_bits = sum((b1 ^ b2).bit_count() for b1, b2 in zip(bloco_base, bloco_mod))
        amostras_bits.append(diff_bits)

    media_bits = sum(amostras_bits) / iteracoes
    desvio_padrao = math.sqrt(sum((x - media_bits) ** 2 for x in amostras_bits) / (iteracoes - 1))
    t_stat = (media_bits - 256.0) / (desvio_padrao / math.sqrt(iteracoes))
    p_val = student_t_two_tailed_p(t_stat, iteracoes - 1)
    return {
        "media_bits": media_bits,
        "desvio_padrao": desvio_padrao,
        "percentual": (media_bits / total_bits_bloco) * 100.0,
        "t_stat": t_stat,
        "p_value": p_val,
    }


# ------------------------------------------------------------------------------
# 2. ESCALABILIDADE DE VOCABULÁRIO (COM E SEM REJECTION SAMPLING)
# ------------------------------------------------------------------------------

def teste_escalabilidade_vocabulario(tamanho_amostra: int = 5000) -> list[dict[str, float | int | str | bool]]:
    chave_64 = "47a5ccbb7e65e5f6074670814f33529a660c05903d66839e35d8f512d46b94b1"
    chave_bytes = normalizar_chave_256bits(chave_64)
    nonce = [10, 25, 43, 77, 99, 12, 84, 53, 21, 65, 33, 90]

    random.seed(99)
    indices_claros = [0 if random.random() < 0.85 else 3 for _ in range(tamanho_amostra)]

    configs = [
        ("N=16", 16, True),
        ("N=20 (Naive mod)", 20, False),
        ("N=20 (Rej. Sampling)", 20, True),
        ("N=64", 64, True),
        ("N=128", 128, True),
        ("N=256 (Optimal)", 256, True),
    ]

    resultados = []
    for label, n_dim, rs in configs:
        deslocamentos = derivar_deslocamentos_chacha20(
            chave_bytes, nonce, tamanho_amostra, n_dim, rejection_sampling=rs
        )
        indices_cif = [(p + d) % n_dim for p, d in zip(indices_claros, deslocamentos)]
        contagens = [0] * n_dim
        for idx in indices_cif:
            contagens[idx] += 1

        entropia = -sum((c / tamanho_amostra) * math.log2(c / tamanho_amostra) for c in contagens if c > 0)
        esperado = tamanho_amostra / n_dim
        chi_sq = sum(((obs - esperado) ** 2) / esperado for obs in contagens)
        df = n_dim - 1
        p_val = chi2_p_value(chi_sq, df)

        resto = 65536 % n_dim
        delta_p = 0.0 if (resto == 0 or rs) else (1.0 / 65536.0)

        resultados.append({
            "label": label,
            "n": n_dim,
            "rejection_sampling": rs,
            "entropia_empirica": entropia,
            "entropia_maxima": math.log2(n_dim),
            "chi_quadrado": chi_sq,
            "df": df,
            "p_value": p_val,
            "delta_p": delta_p,
        })
    return resultados


# ------------------------------------------------------------------------------
# 3. AUDITORIA DE VIÉS MSB EM PREÂMBULO E TAG (PROPOSIÇÃO DE DIVISIBILIDADE)
# ------------------------------------------------------------------------------

def teste_vies_msb_preambulo_tag(amostras: int = 2000) -> dict[str, dict[str, float | int]]:
    """
    Comprova empiricamente a Proposição de Divisibilidade Base-N:
    - N=20 (não potência de 2): dígito MSB do nonce só assume {0, 1} (2/20) e da tag {0..6} (7/20).
    - N=256 (2^8, 8 | gcd(96, 128)=32): 100% uniforme em todos os 256 termos (p > 0.05).
    """
    chave_64 = "47a5ccbb7e65e5f6074670814f33529a660c05903d66839e35d8f512d46b94b1"
    msg = "atacar base amanha esperar reforcos norte"
    random.seed(2026)

    msb_n20_nonce, msb_n20_tag = [], []
    msb_n256_nonce, msb_n256_tag = [], []

    for _ in range(amostras):
        nonce = [random.randint(0, 255) for _ in range(12)]
        p20 = MOTOR_TATICO_20.cifrar(msg, chave_64, nonce)
        p256 = MOTOR_OPTIMO_256.cifrar(msg, chave_64, nonce)
        msb_n20_nonce.append(p20[MOTOR_TATICO_20.len_nonce_tokens - 1])
        msb_n20_tag.append(p20[-1])
        msb_n256_nonce.append(p256[MOTOR_OPTIMO_256.len_nonce_tokens - 1])
        msb_n256_tag.append(p256[-1])

    chi2_20_n, _, p_20_n = teste_qui_quadrado(msb_n20_nonce, 20, PALAVRA_PARA_ID)
    chi2_20_t, _, p_20_t = teste_qui_quadrado(msb_n20_tag, 20, PALAVRA_PARA_ID)
    chi2_256_n, _, p_256_n = teste_qui_quadrado(msb_n256_nonce, 256, MOTOR_OPTIMO_256.cob_para_id)
    chi2_256_t, _, p_256_t = teste_qui_quadrado(msb_n256_tag, 256, MOTOR_OPTIMO_256.cob_para_id)

    hist_20_n = [0] * 20
    for w in msb_n20_nonce:
        hist_20_n[PALAVRA_PARA_ID[w]] += 1
    hist_20_t = [0] * 20
    for w in msb_n20_tag:
        hist_20_t[PALAVRA_PARA_ID[w]] += 1

    return {
        "N20_nonce_msb": {
            "unique_observed": len(set(msb_n20_nonce)),
            "vocab_size": 20,
            "chi_sq": chi2_20_n,
            "p_value": p_20_n,
            "hist_20": hist_20_n,
        },
        "N20_tag_msb": {
            "unique_observed": len(set(msb_n20_tag)),
            "vocab_size": 20,
            "chi_sq": chi2_20_t,
            "p_value": p_20_t,
            "hist_20": hist_20_t,
        },
        "N256_nonce_msb": {
            "unique_observed": len(set(msb_n256_nonce)),
            "vocab_size": 256,
            "chi_sq": chi2_256_n,
            "p_value": p_256_n,
        },
        "N256_tag_msb": {
            "unique_observed": len(set(msb_n256_tag)),
            "vocab_size": 256,
            "chi_sq": chi2_256_t,
            "p_value": p_256_t,
        },
    }


# ------------------------------------------------------------------------------
# 3B. SUBCONJUNTO CORE NIST SP 800-22 REV. 1A (1,000,000 BITS EM PYTHON PURO)
# ------------------------------------------------------------------------------

def teste_nist_sp800_22_core(num_bits: int = 1_000_000) -> dict[str, dict[str, float | bool]]:
    """
    Executa 4 testes canónicos NIST SP 800-22 Rev. 1a (Secções 2.1, 2.2, 2.3 e 2.4)
    sobre 1,000,000 bits produzidos pelos índices cifrados Z_256 sob entrada 85% enviesada.
    Critério padrão NIST: p_value >= 0.01 (nível de significância alpha = 0.01).
    """
    num_bytes = num_bits // 8
    chave_64 = "47a5ccbb7e65e5f6074670814f33529a660c05903d66839e35d8f512d46b94b1"
    chave_bytes = normalizar_chave_256bits(chave_64)
    nonce = [10, 25, 43, 77, 99, 12, 84, 53, 21, 65, 33, 90]

    # Plaintext fortemente enviesado (85% índice 0, 15% índice 3) cifrado em Z_256
    random.seed(2026)
    shifts = derivar_deslocamentos_chacha20(chave_bytes, nonce, num_bytes, 256)
    cipher_bytes = [((0 if random.random() < 0.85 else 3) + s) & 0xFF for s in shifts]

    # 2.1 Frequency (Monobit) Test
    ones = sum(b.bit_count() for b in cipher_bytes)
    s_n = 2 * ones - num_bits
    s_obs = abs(s_n) / math.sqrt(num_bits)
    p_monobit = math.erfc(s_obs / math.sqrt(2.0))

    # 2.2 Block Frequency Test (M = 128 bits = 16 bytes)
    m_block_bytes = 16
    m_bits = m_block_bytes * 8
    n_blocks = num_bytes // m_block_bytes
    chi2_blk = 0.0
    for i in range(0, n_blocks * m_block_bytes, m_block_bytes):
        blk_ones = sum(b.bit_count() for b in cipher_bytes[i:i + m_block_bytes])
        pi_j = blk_ones / m_bits
        chi2_blk += (pi_j - 0.5) ** 2
    chi2_blk *= 4.0 * m_bits
    p_block_freq = chi2_p_value(chi2_blk, n_blocks)

    # 2.3 Runs Test (transições entre bits adjacentes)
    pi = ones / num_bits
    tau = 2.0 / math.sqrt(num_bits)
    if abs(pi - 0.5) >= tau:
        p_runs = 0.0
        v_obs = 0
    else:
        # Conta transições internas em cada byte + fronteiras entre bytes (MSB -> LSB)
        trans_lut = [((x ^ (x >> 1)) & 0x7F).bit_count() for x in range(256)]
        v_obs = 1
        prev_lsb = None
        for b in cipher_bytes:
            v_obs += trans_lut[b]
            if prev_lsb is not None and ((b >> 7) ^ prev_lsb):
                v_obs += 1
            prev_lsb = b & 1
        num = abs(v_obs - 2.0 * num_bits * pi * (1.0 - pi))
        den = 2.0 * math.sqrt(2.0 * num_bits) * pi * (1.0 - pi)
        p_runs = math.erfc(num / den)

    # 2.4 Longest Run of Ones in a Block (NIST SP 800-22 Sec. 2.4: M=10,000 bits, K=6, N=75)
    # 10,000 bits = 1,250 bytes exatos; 75 blocos = 750,000 bits <= 1,000,000 bits
    blk_b = 1250
    n_lr = 75
    probs_lr = [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727]
    bins = [0] * 7
    # Pré-computa (prefix_ones, max_run, suffix_ones) para cada valor de byte 0..255
    byte_run_lut = []
    for x in range(256):
        bits_str = f"{x:08b}"
        pref = len(bits_str) - len(bits_str.lstrip("1"))
        suff = len(bits_str) - len(bits_str.rstrip("1"))
        mx = max((len(seg) for seg in bits_str.split("0")), default=0)
        byte_run_lut.append((pref, mx, suff))

    for blk_idx in range(n_lr):
        start = blk_idx * blk_b
        max_run = 0
        cur_run = 0
        for b in cipher_bytes[start:start + blk_b]:
            if b == 0xFF:
                cur_run += 8
                if cur_run > max_run:
                    max_run = cur_run
            elif b == 0:
                cur_run = 0
            else:
                pref, mx, suff = byte_run_lut[b]
                if cur_run + pref > max_run:
                    max_run = cur_run + pref
                if mx > max_run:
                    max_run = mx
                cur_run = suff
        if max_run <= 10:
            bins[0] += 1
        elif max_run >= 16:
            bins[6] += 1
        else:
            bins[max_run - 10] += 1

    chi2_lr = sum(((bins[i] - n_lr * probs_lr[i]) ** 2) / (n_lr * probs_lr[i]) for i in range(7))
    p_longest_run = chi2_p_value(chi2_lr, 6)

    return {
        "monobit_frequency": {"statistic": s_obs, "p_value": p_monobit, "pass": p_monobit >= 0.01},
        "block_frequency_m128": {"statistic": chi2_blk, "p_value": p_block_freq, "pass": p_block_freq >= 0.01},
        "runs": {"statistic": float(v_obs), "p_value": p_runs, "pass": p_runs >= 0.01},
        "longest_run_m10000": {"statistic": chi2_lr, "p_value": p_longest_run, "pass": p_longest_run >= 0.01},
    }


# ------------------------------------------------------------------------------
# 4. BENCHMARK DE DESEMPENHO JUSTO (WARMUP + R=30 REPETIÇÕES, MÉDIA ± DP)
# ------------------------------------------------------------------------------

def _medir_repeticoes(fn, qtd_tokens: int, repeticoes: int = 30, warmup: int = 3) -> dict[str, float]:
    for _ in range(warmup):
        fn()
    taxas = []
    lat_us = []
    for _ in range(repeticoes):
        t0 = time.perf_counter()
        fn()
        dt = time.perf_counter() - t0
        if dt > 0:
            taxas.append(qtd_tokens / dt)
            lat_us.append((dt * 1e6) / qtd_tokens)
    media_t = sum(taxas) / len(taxas)
    dp_t = math.sqrt(sum((x - media_t) ** 2 for x in taxas) / (len(taxas) - 1))
    media_u = sum(lat_us) / len(lat_us)
    dp_u = math.sqrt(sum((x - media_u) ** 2 for x in lat_us) / (len(lat_us) - 1))
    return {
        "throughput_mean": media_t,
        "throughput_std": dp_t,
        "unit_us_mean": media_u,
        "unit_us_std": dp_u,
    }


def benchmark_desempenho(tamanhos: list[int], repeticoes: int = 30) -> dict[str, dict[int, dict[str, float]]]:
    chave_64 = "47a5ccbb7e65e5f6074670814f33529a660c05903d66839e35d8f512d46b94b1"
    chave_bytes = normalizar_chave_256bits(chave_64)
    nonce = [10, 25, 43, 77, 99, 12, 84, 53, 21, 65, 33, 90]

    perm = {VOCABULARIO[i]: VOCABULARIO[(i + 7) % N] for i in range(N)}
    vig_ids = [PALAVRA_PARA_ID[w] for w in ["norte", "base", "rio"]]

    esquemas = [
        "estatica",
        "vigenere",
        "rc4",
        "chacha20_stream_z256",
        "lexical_aead_z256",
        "rfc8439_base256",
    ]
    resultados: dict[str, dict[int, dict[str, float]]] = {k: {} for k in esquemas}

    random.seed(1234)
    for t in tamanhos:
        tokens_teste = [VOCABULARIO[random.randint(0, N - 1)] for _ in range(t)]
        msg_str = " ".join(tokens_teste)

        resultados["estatica"][t] = _medir_repeticoes(
            lambda: cifra_substituicao_estatica(tokens_teste, perm), t, repeticoes
        )
        resultados["vigenere"][t] = _medir_repeticoes(
            lambda: cifra_vigenere_codebook(tokens_teste, vig_ids), t, repeticoes
        )
        resultados["rc4"][t] = _medir_repeticoes(
            lambda: cifra_rc4_codebook(tokens_teste, chave_bytes), t, repeticoes
        )
        resultados["chacha20_stream_z256"][t] = _medir_repeticoes(
            lambda: cifra_chacha20_stream_tokens(tokens_teste, chave_bytes, nonce, 256), t, repeticoes
        )
        resultados["lexical_aead_z256"][t] = _medir_repeticoes(
            lambda: cifrar_aead_lexical(msg_str, chave_64, nonce), t, repeticoes
        )
        resultados["rfc8439_base256"][t] = _medir_repeticoes(
            lambda: cifrar_rfc8439_base256(msg_str, chave_64, nonce), t, repeticoes
        )

    return resultados


def executar_bateria_estatistica():
    print("=" * 84)
    print(" BATERIA DE AVALIAÇÃO CRIPTOGRÁFICA EMPÍRICA (LEXICAL AEAD Z_256 & Z_20 VS BASELINES)")
    print("=" * 84)

    # 0. Validação Integral RFC 8439
    ok_232 = validar_vetor_rfc8439()
    ok_252 = validar_vetor_poly1305_rfc8439()
    ok_282 = validar_vetor_aead_rfc8439_secao282()
    assert ok_232 and ok_252 and ok_282
    print("\n[+] 0. VALIDAÇÃO INTEGRAL IETF RFC 8439 (2.3.2 [64B], 2.5.2, 2.8.2 [114B+16B]): CONFORME (OK)")

    # 1. Strict Avalanche Criterion (SAC)
    print("\n[+] 1. STRICT AVALANCHE CRITERION (SAC, n=300 iterações)")
    av_key = teste_avalanche_chacha20(300)
    av_nonce = teste_avalanche_nonce_chacha20(300)
    print(f" -> Key (256-bit)  : {av_key['media_bits']:.2f} ± {av_key['desvio_padrao']:.2f} bits "
          f"({av_key['percentual']:.2f}%) | t = {av_key['t_stat']:+.3f} | p = {av_key['p_value']:.3f}")
    print(f" -> Nonce (96-bit) : {av_nonce['media_bits']:.2f} ± {av_nonce['desvio_padrao']:.2f} bits "
          f"({av_nonce['percentual']:.2f}%) | t = {av_nonce['t_stat']:+.3f} | p = {av_nonce['p_value']:.3f}")

    # 2. Entropia, Chi-Square e Autocorrelação sob Texto Altamente Enviesado (85% skew, N=20, RS=True)
    print("\n[+] 2. DISPERSÃO E INDEPENDÊNCIA TEMPORAL SOB TEXTO 85% ENVIESADO (5,000 tokens, N=20)")
    tamanho_amostra = 5000
    random.seed(99)
    tokens_vies = ["atacar" if random.random() < 0.85 else "base" for _ in range(tamanho_amostra)]
    msg_vies = " ".join(tokens_vies)

    chave_64 = "47a5ccbb7e65e5f6074670814f33529a660c05903d66839e35d8f512d46b94b1"
    chave_bytes = normalizar_chave_256bits(chave_64)
    nonce = [10, 25, 43, 77, 99, 12, 84, 53, 21, 65, 33, 90]
    perm = {VOCABULARIO[i]: VOCABULARIO[(i + 7) % N] for i in range(N)}
    vig_ids = [PALAVRA_PARA_ID[w] for w in ["norte", "base", "rio"]]

    perfis_disp = [
        ("Biased Plaintext", tokens_vies),
        ("Static Substitution", cifra_substituicao_estatica(tokens_vies, perm)),
        ("Vigenere (L=3)", cifra_vigenere_codebook(tokens_vies, vig_ids)),
        ("RC4 Stream Codebook", cifra_rc4_codebook(tokens_vies, chave_bytes)),
        ("ChaCha20 Z_20 (RS)", cifrar_com_chacha20(msg_vies, chave_64, nonce, rejection_sampling=True)),
    ]

    ent_max = math.log2(N)
    limite_r1 = 1.96 / math.sqrt(tamanho_amostra)
    print(f" -> Teto H_max = {ent_max:.4f} bits | E[Chi2 | H0] = {N - 1}.0 | Limite |r1| (95%) < {limite_r1:.4f}")
    tabela_disp = {}
    for nome, seq in perfis_disp:
        h = calcular_entropia_shannon(seq)
        eta = (h / ent_max) * 100.0
        chi2, _, p_val = teste_qui_quadrado(seq, N)
        r1 = teste_autocorrelacao_serial(seq, 1)
        tabela_disp[nome] = {"H": h, "eta": eta, "chi2": chi2, "p_value": p_val, "r1": r1}
        p_str = "< 1e-100" if p_val < 1e-100 else f"{p_val:.3f}"
        print(f" -> {nome:<22}: H={h:.4f} ({eta:6.2f}%) | Chi2={chi2:8.1f} | p={p_str:<8} | r1={r1:+.4f}")

    # 3. Escalabilidade de Vocabulário
    print("\n[+] 3. ESCALABILIDADE DE LÉXICO (N = 16, 20 [Naive vs RS], 64, 128, 256)")
    escala = teste_escalabilidade_vocabulario(5000)
    for row in escala:
        print(f" -> {row['label']:<21}: H={row['entropia_empirica']:.4f}/{row['entropia_maxima']:.4f} "
              f"| Chi2={row['chi_quadrado']:6.1f} (df={row['df']:3d}, p={row['p_value']:.3f}) | Δp={row['delta_p']:.2e}")

    # 4. Auditoria de Viés MSB (N=20 vs N=256)
    print("\n[+] 4. AUDITORIA DE DISTINGUIDOR MSB EM PREÂMBULO E TAG (2,000 pacotes)")
    msb = teste_vies_msb_preambulo_tag(2000)
    for k, v in msb.items():
        p_str = "< 1e-100" if v["p_value"] < 1e-100 else f"{v['p_value']:.3f}"
        print(f" -> {k:<16}: Cobertura = {v['unique_observed']:3d}/{v['vocab_size']:3d} termos | Chi2 = {v['chi_sq']:8.1f} | p = {p_str}")

    # 4B. Subconjunto NIST SP 800-22 (1,000,000 bits) + Autocorrelação Multi-Lag (r1..r10)
    print("\n[+] 4B. NIST SP 800-22 CORE SUBSET (1,000,000 bits Z_256) & MULTI-LAG AUTOCORR (r1..r10)")
    nist = teste_nist_sp800_22_core(1_000_000)
    for nome_t, res_t in nist.items():
        status = "PASS" if res_t["pass"] else "FAIL"
        print(f" -> NIST {nome_t:<22}: stat = {res_t['statistic']:9.4f} | p = {res_t['p_value']:.4f} [{status}]")
    seq_chacha20 = perfis_disp[-1][1]
    multi_lag = {f"r_{k}": teste_autocorrelacao_serial(seq_chacha20, k) for k in range(1, 11)}
    max_abs_rk = max(abs(v) for v in multi_lag.values())
    print(f" -> Multi-Lag r1..r10 (m=5,000): max |r_k| = {max_abs_rk:.4f} (limiar 95%: 0.0277, Bonferroni 99.5%: 0.0397)")

    # 5. Benchmark de Throughput (R=30 repetições)
    print("\n[+] 5. BENCHMARK DE THROUGHPUT (R=30 repetições após warmup, média ± DP)")
    tamanhos = [50, 500, 2000]
    bench = benchmark_desempenho(tamanhos, repeticoes=30)
    for t in tamanhos:
        print(f" -> Amostra {t} tokens operacionais:")
        for esq in ["estatica", "vigenere", "rc4", "chacha20_stream_z256", "lexical_aead_z256", "rfc8439_base256"]:
            m = bench[esq][t]
            print(f"    - {esq:<22}: {m['throughput_mean']:>11,.0f} ± {m['throughput_std']:>9,.0f} tok/s "
                  f"({m['unit_us_mean']:.2f} ± {m['unit_us_std']:.2f} µs/tok)")

    out_path = Path(__file__).resolve().parent / "resultado_benchmark.json"
    payload_json = {
        "rfc8439_valid": {"sec_2_3_2_full64B": ok_232, "sec_2_5_2": ok_252, "sec_2_8_2_full": ok_282},
        "sac": {"key": av_key, "nonce": av_nonce},
        "dispersion_n20": tabela_disp,
        "multi_lag_autocorr": {"lags": multi_lag, "max_abs_r": max_abs_rk},
        "scaling": escala,
        "msb_audit": msb,
        "nist_sp800_22_1m_bits": nist,
        "throughput": bench,
    }
    out_path.write_text(json.dumps(payload_json, indent=2), encoding="utf-8")
    print(f"\n[OK] Relatório estatístico salvo em '{out_path.name}'.")


if __name__ == "__main__":
    executar_bateria_estatistica()
