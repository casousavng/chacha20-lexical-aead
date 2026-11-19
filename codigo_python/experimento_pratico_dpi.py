# ==============================================================================
# EXPERIMENTO EMPÍRICO: SIMULAÇÃO DE FILTROS HEURÍSTICOS DE PERÍMETRO (DPI)
# E RESISTÊNCIA ANTI-ADULTERAÇÃO (LEXICAL AEAD Z_256 VS BASELINES)
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
    MOTOR_OPTIMO_256,
    MOTOR_TATICO_20,
    normalizar_chave_256bits,
    chacha20_block,
    derivar_chave_poly1305,
    cifrar_aead_lexical,
    decifrar_aead_lexical,
    cifrar_rfc8439_base256,
)
from poly1305 import poly1305_mac, construir_mac_data_rfc8439

WATCHLIST_OPERACIONAL = {"atacar", "evacuar", "reforcos", "combustivel", "recuar", "urgente"}


# ------------------------------------------------------------------------------
# FILTROS HEURÍSTICOS DE INSPEÇÃO DE PERÍMETRO (SIMULAÇÃO STATELESS)
# ------------------------------------------------------------------------------

def calcular_entropia_bytes(payload_bytes: bytes) -> float:
    """Entropia de Shannon a nível de byte (0 a 8 bits/byte)."""
    if not payload_bytes:
        return 0.0
    contagens = [0] * 256
    for b in payload_bytes:
        contagens[b] += 1
    total = len(payload_bytes)
    return -sum((c / total) * math.log2(c / total) for c in contagens if c > 0)


def calcular_taxa_caracteres_imprimiveis(payload_bytes: bytes) -> float:
    """Proporção de caracteres ASCII imprimíveis (0x20..0x7E + whitespace)."""
    if not payload_bytes:
        return 0.0
    imprimiveis = sum(1 for b in payload_bytes if 32 <= b <= 126 or b in (9, 10, 13))
    return imprimiveis / len(payload_bytes)


def dpi_inspecao_heuristica(payload_bytes: bytes) -> dict[str, bool]:
    """
    Avalia três regras heurísticas stateless típicas de perímetro:
      - F1 (Entropia de byte): H_b >= 6.8 bits/byte
      - F2 (Binário / não-imprimível): rho_print < 85%
      - F3 (Watchlist IDS de palavras-chave): presença de termos táticos sensíveis
    """
    alerta_entropia = calcular_entropia_bytes(payload_bytes) >= 6.8
    alerta_binario = calcular_taxa_caracteres_imprimiveis(payload_bytes) < 0.85
    try:
        texto = payload_bytes.decode("ascii").lower().split()
        alerta_watchlist = any(w in WATCHLIST_OPERACIONAL for w in texto)
    except UnicodeDecodeError:
        alerta_watchlist = False

    return {
        "alerta_entropia": alerta_entropia,
        "alerta_binario": alerta_binario,
        "alerta_watchlist": alerta_watchlist,
        "sinalizado_total": alerta_entropia or alerta_binario or alerta_watchlist,
    }


# ------------------------------------------------------------------------------
# GERADORES DE CORPUS E TRÁFEGO
# ------------------------------------------------------------------------------

FRASES_CURTAS = [
    "atacar base amanha esperar reforcos norte",
    "recuar posicao porto evacuar urgente sul",
    "proteger combustivel suprimentos confirmado ponte noite",
    "cancelar posicao esperar reforcos base rio",
    "urgente evacuar porto amanha proteger combustivel",
    "confirmado atacar norte suprimentos reforcos base",
    "esperar reforcos noite posicao proteger ponte",
    "recuar sul evacuar base cancelar amanha",
]


def gerar_mensagem_operacional(num_palavras: int) -> str:
    """Gera mensagem operacional sintética com comprimento controlado."""
    if num_palavras == 6:
        return random.choice(FRASES_CURTAS)
    blocos = []
    while len(blocos) < num_palavras:
        blocos.extend(random.choice(FRASES_CURTAS).split())
    return " ".join(blocos[:num_palavras])


def gerar_pacote_rfc8439_binario(chave_bytes: list[int], nonce_bytes: list[int], msg_str: str) -> bytes:
    """Gera pacote binário RFC 8439 ChaCha20-Poly1305 completo: Nonce(12B) || CT || Tag(16B)."""
    dados = list(msg_str.encode("utf-8"))
    keystream = []
    c = 1
    while len(keystream) < len(dados):
        keystream.extend(chacha20_block(chave_bytes, c, nonce_bytes))
        c += 1
    ct_bytes = [b ^ k for b, k in zip(dados, keystream[:len(dados)])]
    otk = derivar_chave_poly1305(chave_bytes, nonce_bytes)
    mac_data = construir_mac_data_rfc8439([], ct_bytes)
    tag = poly1305_mac(mac_data, otk)
    return bytes(nonce_bytes + ct_bytes + tag)


def executar_regime(nome_regime: str, num_palavras: int, amostras: int, chave_64: str, chave_bytes: list[int]) -> dict:
    perfis_nomes = [
        "Plaintext Tactical",
        "Raw RFC 8439 Binary",
        "Lexical AEAD Z_20 (Legacy)",
        "RFC 8439 + Base-256 Cover",
        "Lexical AEAD Z_256 (Ours)",
    ]
    acum = {
        p: {
            "entropia": [],
            "imprimivel": [],
            "f1_entropia": 0,
            "f2_binario": 0,
            "f3_watchlist": 0,
            "sinalizado_total": 0,
            "bytes_total": 0,
            "tokens_total": 0,
            "latencia_us": [],
        }
        for p in perfis_nomes
    }

    for _ in range(amostras):
        msg = gerar_mensagem_operacional(num_palavras)
        # Nonce determinístico via seed apenas para reprodutibilidade do ensaio;
        # em produção app.cifrar_aead_lexical(msg, chave) usa os.urandom(12).
        nonce = [random.randint(0, 255) for _ in range(12)]

        # 1. Plaintext Tactical
        t0 = time.perf_counter_ns()
        pkt_plain = msg.encode("utf-8")
        lat = (time.perf_counter_ns() - t0) / 1000.0
        _registar(acum["Plaintext Tactical"], pkt_plain, num_palavras, lat)

        # 2. Raw RFC 8439 Binary (WireGuard-style payload)
        t0 = time.perf_counter_ns()
        pkt_bin = gerar_pacote_rfc8439_binario(chave_bytes, nonce, msg)
        lat = (time.perf_counter_ns() - t0) / 1000.0
        _registar(acum["Raw RFC 8439 Binary"], pkt_bin, 0, lat)

        # 3. Lexical AEAD Z_20 (Legacy Tactical Vocab)
        t0 = time.perf_counter_ns()
        toks_20 = MOTOR_TATICO_20.cifrar(msg, chave_64, nonce)
        pkt_20 = " ".join(toks_20).encode("utf-8")
        lat = (time.perf_counter_ns() - t0) / 1000.0
        _registar(acum["Lexical AEAD Z_20 (Legacy)"], pkt_20, len(toks_20), lat)

        # 4. Baseline: Standard RFC 8439 + Base-256 Cover Encoding
        t0 = time.perf_counter_ns()
        toks_b256 = cifrar_rfc8439_base256(msg, chave_64, nonce)
        pkt_b256 = " ".join(toks_b256).encode("utf-8")
        lat = (time.perf_counter_ns() - t0) / 1000.0
        _registar(acum["RFC 8439 + Base-256 Cover"], pkt_b256, len(toks_b256), lat)

        # 5. Proposed: Lexical AEAD Z_256 (Decoupled Benign Cover Lexicon)
        t0 = time.perf_counter_ns()
        toks_256 = cifrar_aead_lexical(msg, chave_64, nonce)
        pkt_256 = " ".join(toks_256).encode("utf-8")
        lat = (time.perf_counter_ns() - t0) / 1000.0
        _registar(acum["Lexical AEAD Z_256 (Ours)"], pkt_256, len(toks_256), lat)

    resumo = {}
    print(f"\n--- {nome_regime} ({num_palavras} palavras/msg, {amostras} pacotes/perfil) ---")
    print(
        f"{'Perfil':<27} | {'H_b':>6} | {'Print%':>6} | {'Size(B)':>7} | {'Tok':>4} | "
        f"{'F1:Ent':>6} | {'F2:Bin':>6} | {'F3:IDS':>6} | {'Evade%':>6} | {'Lat(us)':>7}"
    )
    print("-" * 112)

    for nome in perfis_nomes:
        d = acum[nome]
        media_h = sum(d["entropia"]) / amostras
        media_p = (sum(d["imprimivel"]) / amostras) * 100.0
        tam_b = d["bytes_total"] / amostras
        tam_t = d["tokens_total"] / amostras
        f1 = (d["f1_entropia"] / amostras) * 100.0
        f2 = (d["f2_binario"] / amostras) * 100.0
        f3 = (d["f3_watchlist"] / amostras) * 100.0
        det = (d["sinalizado_total"] / amostras) * 100.0
        evasao = 100.0 - det
        lat_m = sum(d["latencia_us"]) / amostras

        resumo[nome] = {
            "media_entropia": media_h,
            "media_imprimivel": media_p,
            "tamanho_medio_bytes": tam_b,
            "tokens_medios": tam_t,
            "alerta_f1_entropia_pct": f1,
            "alerta_f2_binario_pct": f2,
            "alerta_f3_watchlist_pct": f3,
            "taxa_detecao_total_pct": det,
            "taxa_evasao_pct": evasao,
            "latencia_us": lat_m,
        }
        tok_str = f"{tam_t:4.0f}" if tam_t > 0 else "  --"
        print(
            f"{nome:<27} | {media_h:6.4f} | {media_p:5.1f}% | {tam_b:7.1f} | {tok_str} | "
            f"{f1:5.1f}% | {f2:5.1f}% | {f3:5.1f}% | {evasao:5.1f}% | {lat_m:7.1f}"
        )

    return resumo


def _registar(dest: dict, pkt: bytes, num_tokens: int, lat_us: float) -> None:
    h = calcular_entropia_bytes(pkt)
    p = calcular_taxa_caracteres_imprimiveis(pkt)
    r = dpi_inspecao_heuristica(pkt)
    dest["entropia"].append(h)
    dest["imprimivel"].append(p)
    dest["bytes_total"] += len(pkt)
    dest["tokens_total"] += num_tokens
    dest["latencia_us"].append(lat_us)
    if r["alerta_entropia"]:
        dest["f1_entropia"] += 1
    if r["alerta_binario"]:
        dest["f2_binario"] += 1
    if r["alerta_watchlist"]:
        dest["f3_watchlist"] += 1
    if r["sinalizado_total"]:
        dest["sinalizado_total"] += 1


def executar_testes_tamper(chave_64: str, por_categoria: int = 250) -> dict[str, int]:
    """
    Avalia 1.000 tentativas de adulteração em 4 vetores de ataque distintos (250 cada):
    1. Mutação no ciphertext; 2. Mutação no preâmbulo Nonce;
    3. Mutação na Tag Poly1305; 4. Adulteração de AAD / Injeção OOV / Overflow Não-Canónico.
    """
    aad_legit = "canal=tatico;versao=2"
    contadores = {
        "ciphertext_rejeitados": 0,
        "nonce_rejeitados": 0,
        "tag_rejeitados": 0,
        "aad_e_canonico_rejeitados": 0,
        "total_por_categoria": por_categoria,
    }

    for i in range(por_categoria):
        msg = gerar_mensagem_operacional(6)
        nonce = [random.randint(0, 255) for _ in range(12)]
        pkt = cifrar_aead_lexical(msg, chave_64, nonce, dados_associados=aad_legit)

        # Vetor 1: Ciphertext
        c1 = list(pkt)
        idx = random.randint(12, len(c1) - 17)
        c1[idx] = "abacate" if c1[idx] != "abacate" else "abelha"
        try:
            decifrar_aead_lexical(c1, chave_64, dados_associados=aad_legit)
        except ValueError:
            contadores["ciphertext_rejeitados"] += 1

        # Vetor 2: Nonce preamble
        c2 = list(pkt)
        idx = random.randint(0, 11)
        c2[idx] = "abacate" if c2[idx] != "abacate" else "abelha"
        try:
            decifrar_aead_lexical(c2, chave_64, dados_associados=aad_legit)
        except ValueError:
            contadores["nonce_rejeitados"] += 1

        # Vetor 3: Poly1305 tag suffix
        c3 = list(pkt)
        idx = random.randint(len(c3) - 16, len(c3) - 1)
        c3[idx] = "abacate" if c3[idx] != "abacate" else "abelha"
        try:
            decifrar_aead_lexical(c3, chave_64, dados_associados=aad_legit)
        except ValueError:
            contadores["tag_rejeitados"] += 1

        # Vetor 4: Alterna entre AAD adulterado, OOV e Overflow Não-Canónico N=20 (+2^96)
        if i % 3 == 0:
            try:
                decifrar_aead_lexical(pkt, chave_64, dados_associados="canal=atacante;versao=2")
            except ValueError:
                contadores["aad_e_canonico_rejeitados"] += 1
        elif i % 3 == 1:
            c4 = list(pkt)
            c4[0] = "token_fora_vocab"
            try:
                decifrar_aead_lexical(c4, chave_64, dados_associados=aad_legit)
            except ValueError:
                contadores["aad_e_canonico_rejeitados"] += 1
        else:
            p20 = MOTOR_TATICO_20.cifrar(msg, chave_64, nonce)
            val_n = sum(b << (8 * j) for j, b in enumerate(nonce)) + (1 << 96)
            forged = []
            tmp = val_n
            for _ in range(MOTOR_TATICO_20.len_nonce_tokens):
                forged.append(VOCABULARIO[tmp % 20])
                tmp //= 20
            try:
                MOTOR_TATICO_20.decifrar(forged + p20[23:], chave_64)
            except ValueError:
                contadores["aad_e_canonico_rejeitados"] += 1

    return contadores


def executar_redteam_zipf(chave_64: str, trials: int = 1000) -> dict:
    """
    Auto-ataque red-team: detetor estatístico de razão de verosimilhança (LLR) entre
    um modelo de prosa Zipf (s=1) sobre o léxico de cobertura e o modelo uniforme.
    Tráfego 'natural' é um PROXY sintético Zipf (não corpus real); o fluxo Lexical AEAD
    é uniforme por construção. Mede acerto do atacante em função da janela W de tokens.
    """
    cob = VOCABULARIO_COBERTURA_256
    n = len(cob)
    pesos = [1.0 / (r + 1) for r in range(n)]
    z = sum(pesos)
    p_zipf = [w / z for w in pesos]
    log_ratio = [math.log(p_zipf[i] * n) for i in range(n)]  # log(P_zipf/P_unif)
    cum = []
    acc = 0.0
    for p in p_zipf:
        acc += p
        cum.append(acc)

    def amostra_zipf() -> int:
        u = random.random()
        lo, hi = 0, n - 1
        while lo < hi:
            mid = (lo + hi) // 2
            if cum[mid] >= u:
                hi = mid
            else:
                lo = mid + 1
        return lo

    idx_cob = MOTOR_OPTIMO_256.cob_para_id
    res = {}
    for w in (10, 20, 40, 88):
        acertos_aead = 0
        acertos_prosa = 0
        for _ in range(trials):
            # Pacote AEAD com exatamente w tokens totais (28 de metadados => w-28 payload; usa janela dos w primeiros)
            msg = gerar_mensagem_operacional(60)
            toks = cifrar_aead_lexical(msg, chave_64, [random.randint(0, 255) for _ in range(12)])
            janela = toks[:w]
            llr = sum(log_ratio[idx_cob[t]] for t in janela)
            if llr < 0:  # mais verosímil uniforme => classificado como cifrado
                acertos_aead += 1
            prosa = [amostra_zipf() for _ in range(w)]
            llr_p = sum(log_ratio[i] for i in prosa)
            if llr_p >= 0:  # classificado corretamente como prosa
                acertos_prosa += 1
        res[str(w)] = {
            "tpr_detecao_aead_pct": acertos_aead / trials * 100.0,
            "tnr_prosa_pct": acertos_prosa / trials * 100.0,
        }
    return res


def executar_loopback_udp(chave_64: str, chave_bytes: list[int], num_pkts: int = 300, palavras: int = 60) -> dict:
    """
    Transporte real em socket UDP loopback (127.0.0.1, stdlib): envia pacotes de 3 perfis,
    recebe do kernel e aplica filtros F1-F3 sobre os datagramas recebidos.
    MTU de payload UDP/IPv4 Ethernet = 1472 B (acima => fragmentaria em rede real; o loopback macOS tem MTU maior).
    """
    import socket

    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0))
    rx.settimeout(2.0)
    addr = rx.getsockname()
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    perfis = {"Raw RFC 8439 Binary": 0, "RFC 8439 + Base-256 Cover": 0, "Lexical AEAD Z_256 (Ours)": 0}
    out = {k: {"recebidos": 0, "sinalizados": 0, "acima_mtu_1472": 0} for k in perfis}
    random.seed(7)
    for _ in range(num_pkts):
        msg = gerar_mensagem_operacional(palavras)
        nonce = [random.randint(0, 255) for _ in range(12)]
        pkts = {
            "Raw RFC 8439 Binary": gerar_pacote_rfc8439_binario(chave_bytes, nonce, msg),
            "RFC 8439 + Base-256 Cover": " ".join(cifrar_rfc8439_base256(msg, chave_64, nonce)).encode("utf-8"),
            "Lexical AEAD Z_256 (Ours)": " ".join(cifrar_aead_lexical(msg, chave_64, nonce)).encode("utf-8"),
        }
        for nome, pkt in pkts.items():
            tx.sendto(pkt, addr)
            data, _ = rx.recvfrom(65535)
            out[nome]["recebidos"] += 1
            if len(data) > 1472:
                out[nome]["acima_mtu_1472"] += 1
            if dpi_inspecao_heuristica(data)["sinalizado_total"]:
                out[nome]["sinalizados"] += 1
    rx.close()
    tx.close()
    return out


def executar_experimento_dpi(amostras_por_perfil: int = 1000):
    print("=" * 112)
    print(f" SIMULAÇÃO EMPÍRICA DE FILTROS HEURÍSTICOS DPI ({amostras_por_perfil} PACOTES/PERFIL EM 2 REGIMES)")
    print("=" * 112)

    chave_64 = "47a5ccbb7e65e5f6074670814f33529a660c05903d66839e35d8f512d46b94b1"
    chave_bytes = normalizar_chave_256bits(chave_64)
    random.seed(2026)

    res_curto = executar_regime("REGIME A: Comandos Táticos Curtos", 6, amostras_por_perfil, chave_64, chave_bytes)
    res_longo = executar_regime("REGIME B: Relatórios Operacionais Extensos", 60, amostras_por_perfil, chave_64, chave_bytes)

    redteam = executar_redteam_zipf(chave_64, trials=1000)
    print("\n[+] RED-TEAM: DETETOR LLR ZIPF vs UNIFORME (1.000 tentativas por janela W)")
    for w, r in redteam.items():
        print(f" -> W={w:>2} tokens: deteção do fluxo AEAD = {r['tpr_detecao_aead_pct']:5.1f}% | prosa Zipf corretamente aceite = {r['tnr_prosa_pct']:5.1f}%")

    loop = executar_loopback_udp(chave_64, chave_bytes, num_pkts=300, palavras=60)
    print("\n[+] TRANSPORTE UDP LOOPBACK REAL (300 datagramas/perfil, 60 palavras):")
    for nome, r in loop.items():
        print(f" -> {nome:<27}: recebidos={r['recebidos']} | sinalizados F1-F3={r['sinalizados']} | > 1472 B (fragmentaria)={r['acima_mtu_1472']}")

    tamper = executar_testes_tamper(chave_64, por_categoria=250)
    total_rej = (
        tamper["ciphertext_rejeitados"]
        + tamper["nonce_rejeitados"]
        + tamper["tag_rejeitados"]
        + tamper["aad_e_canonico_rejeitados"]
    )
    total_trials = tamper["total_por_categoria"] * 4
    print("\n[+] AVALIAÇÃO INTEGRAL DE INTEGRIDADE ANTI-ADULTERAÇÃO (4 VETORES DE ATAQUE):")
    print(f" -> Ciphertext : {tamper['ciphertext_rejeitados']}/{tamper['total_por_categoria']}")
    print(f" -> Nonce Pre. : {tamper['nonce_rejeitados']}/{tamper['total_por_categoria']}")
    print(f" -> Tag Suffix : {tamper['tag_rejeitados']}/{tamper['total_por_categoria']}")
    print(f" -> AAD/OOV/NC : {tamper['aad_e_canonico_rejeitados']}/{tamper['total_por_categoria']}")
    print(f" -> TOTAL      : {total_rej}/{total_trials} ({(total_rej / total_trials) * 100.0:.1f}%)")

    out_path = Path(__file__).resolve().parent / "resultado_experimento_dpi.json"
    dados_relatorio = {
        "regime_curto_6w": res_curto,
        "regime_extenso_60w": res_longo,
        "tamper_resistance": tamper,
        "redteam_zipf_llr": redteam,
        "udp_loopback_60w": loop,
    }
    out_path.write_text(json.dumps(dados_relatorio, indent=2), encoding="utf-8")
    print(f"\n[OK] Resultados gravados em '{out_path.name}'.")


if __name__ == "__main__":
    executar_experimento_dpi(amostras_por_perfil=1000)
