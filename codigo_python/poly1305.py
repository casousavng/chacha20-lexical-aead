# ==============================================================================
# MOTOR POLY1305 PURO (RFC 8439 SECÇÃO 2.5 & 2.8) - ZERO IMPORTS EXTERNOS
# ==============================================================================

def poly1305_clamp(r_bytes: list[int]) -> int:
    """Aplica o 'clamping' de 16 bytes na chave r conforme a RFC 8439 Secção 2.5."""
    r = list(r_bytes[:16])
    r[3] &= 15
    r[7] &= 15
    r[11] &= 15
    r[15] &= 15
    r[4] &= 252
    r[8] &= 252
    r[12] &= 252
    val = 0
    for i in range(16):
        val |= (r[i] << (8 * i))
    return val


def le_bytes_to_num(b: list[int]) -> int:
    """Converte bytes little-endian para inteiro de precisão arbitrária."""
    val = 0
    for i, x in enumerate(b):
        val |= (x << (8 * i))
    return val


def num_to_16_le_bytes(n: int) -> list[int]:
    """Converte inteiro de 128 bits para 16 bytes little-endian."""
    out = []
    for _ in range(16):
        out.append(n & 0xFF)
        n >>= 8
    return out


def poly1305_mac(msg_bytes: list[int], key_32bytes: list[int]) -> list[int]:
    """
    Calcula a tag de autenticação de 16 bytes (128 bits) segundo a RFC 8439.
    Primo de avaliação: p = 2^130 - 5.
    """
    if len(key_32bytes) != 32:
        raise ValueError("A chave Poly1305 deve conter exatamente 32 bytes.")

    r = poly1305_clamp(key_32bytes[:16])
    s = le_bytes_to_num(key_32bytes[16:32])
    p = (1 << 130) - 5
    a = 0

    # Processa blocos de 16 bytes
    for i in range(0, len(msg_bytes), 16):
        bloco = msg_bytes[i:i + 16]
        # Adiciona o byte 0x01 após o bloco (define o bit 2^(8*len(bloco)))
        bloco_com_um = list(bloco) + [0x01]
        n = le_bytes_to_num(bloco_com_um)
        a = ((a + n) * r) % p

    tag_int = (a + s) % (1 << 128)
    return num_to_16_le_bytes(tag_int)


def constant_time_compare(a: list[int], b: list[int]) -> bool:
    """
    Comparação sem retorno antecipado (early-exit free) de duas sequências de bytes.
    Para tags de comprimento fixo (l = 16 bytes), executa exatamente 16 iterações XOR/OR
    em tempo O(l) = O(1) para tags fixas, mitigando oráculos de temporização na camada aplicacional.
    """
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= (x ^ y)
    return diff == 0


def construir_mac_data_rfc8439(aad_bytes: list[int], corpo_cifrado_bytes: list[int]) -> list[int]:
    """
    Monta a sequência de bytes para o autenticador Poly1305 segundo a RFC 8439 (Secção 2.8):
    1. AAD (Dados Associados Autenticados)
    2. Preenchimento de zeros para múltiplo de 16 bytes (pad16)
    3. Ciphertext (Carga cifrada)
    4. Preenchimento de zeros para múltiplo de 16 bytes (pad16)
    5. Comprimento do AAD em 64 bits (8 bytes little-endian)
    6. Comprimento do Ciphertext em 64 bits (8 bytes little-endian)
    """
    pad_aad = (16 - (len(aad_bytes) % 16)) % 16
    pad_ct = (16 - (len(corpo_cifrado_bytes) % 16)) % 16

    len_aad_8b = [(len(aad_bytes) >> (8 * i)) & 0xFF for i in range(8)]
    len_ct_8b = [(len(corpo_cifrado_bytes) >> (8 * i)) & 0xFF for i in range(8)]

    return (
        list(aad_bytes)
        + ([0] * pad_aad)
        + list(corpo_cifrado_bytes)
        + ([0] * pad_ct)
        + len_aad_8b
        + len_ct_8b
    )


def validar_vetor_poly1305_rfc8439() -> bool:
    """
    Valida contra o Vetor de Teste Oficial da RFC 8439 (Secção 2.5.2):
    Key: 85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b
    Msg: "Cryptographic Forum Research Group"
    Tag: a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9
    """
    key = [
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b
    ]
    msg = list("Cryptographic Forum Research Group".encode("ascii"))
    tag_esperada = [
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
        0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9
    ]
    tag_calculada = poly1305_mac(msg, key)
    return constant_time_compare(tag_calculada, tag_esperada)


if __name__ == "__main__":
    assert validar_vetor_poly1305_rfc8439(), "Falha no vetor oficial Poly1305 RFC 8439!"
    assert constant_time_compare([1, 2, 3], [1, 2, 3]), "Falha constant_time_compare igual!"
    assert not constant_time_compare([1, 2, 3], [1, 2, 4]), "Falha constant_time_compare diferente!"
    assert not constant_time_compare([1, 2], [1, 2, 3]), "Falha constant_time_compare tamanhos!"
    print("[OK] Poly1305 e Comparação em Tempo Constante validados com sucesso.")
