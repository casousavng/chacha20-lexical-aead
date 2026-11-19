# ==============================================================================
# LEXICAL AEAD COM MOTOR CHACHA20-POLY1305 (RFC 8439) EM PYTHON PURO
# ZERO DEPENDÊNCIAS EXTERNAS (APENAS STDLIB: math, os)
# ARQUITETURA: LÉXICO DE COBERTURA DESACOPLADO (N=256 ÓTIMO OU N ARBITRÁRIO)
#              + REJECTION SAMPLING + CANONICAL BOUNDS + RANDOMIZED PADDING
# ==============================================================================
import math
import os
from poly1305 import (
    poly1305_mac,
    validar_vetor_poly1305_rfc8439,
    constant_time_compare,
    construir_mac_data_rfc8439,
)

# 1. Vocabulário Operacional Tático de Referência (20 termos - caso de estudo N=20)
VOCABULARIO = [
    "atacar", "recuar", "amanha", "base", "norte", "sul",
    "esperar", "reforcos", "suprimentos", "confirmado",
    "cancelar", "urgente", "porto", "noite", "ponte",
    "rio", "evacuar", "proteger", "combustivel", "posicao"
]

N = len(VOCABULARIO)
PALAVRA_PARA_ID = {p: i for i, p in enumerate(VOCABULARIO)}
ID_PARA_PALAVRA = {i: p for i, p in enumerate(VOCABULARIO)}

# 2. Léxico de Cobertura Benigno (N=256 = 2^8, ótimo: b=8 | gcd(96, 128)=32)
# 256 palavras quotidianas em português (ASCII puro, minúsculas, sem termos militares)
VOCABULARIO_COBERTURA_256 = [
    "abacate", "abelha", "abrigo", "acorde", "agenda", "agosto", "agua", "alface",
    "algodao", "alivio", "almoco", "altura", "amarelo", "amizade", "amora", "ancora",
    "andar", "anel", "anexo", "antena", "apito", "aplauso", "arame", "arco",
    "areia", "aroma", "arroz", "arvore", "asa", "asfalto", "assento", "astro",
    "atelier", "atlas", "aurora", "aveia", "avenida", "aviao", "azeite", "azul",
    "bacia", "bagagem", "baia", "bairro", "balanco", "balao", "balde", "bambu",
    "banana", "banco", "bandeja", "banho", "barco", "barra", "barril", "batata",
    "beira", "beleza", "berco", "bexiga", "bico", "bilhete", "biombo", "biscoito",
    "bloco", "blusa", "boca", "bola", "bolo", "bolsa", "boneca", "borda",
    "bosque", "bota", "botao", "branco", "brisa", "broca", "broto", "bule",
    "cabana", "cabelo", "cabide", "cabo", "cacau", "cacho", "cadeira", "caderno",
    "cafe", "caixa", "calca", "calda", "calma", "calor", "cama", "camelo",
    "caminho", "camisa", "campo", "canal", "caneca", "canela", "caneta", "canoa",
    "canto", "capa", "capim", "caracol", "cardume", "carimbo", "carinho", "carne",
    "carpete", "carro", "carta", "cartaz", "casa", "casaco", "casca", "castelo",
    "cavalo", "cebola", "cedro", "cenario", "cenoura", "centro", "cera", "cerca",
    "cereal", "cereja", "cesta", "cetim", "chale", "chama", "chapeu", "chave",
    "chegada", "cheiro", "chinelo", "chuva", "ciclo", "cidade", "cidra", "cinema",
    "cinto", "cinza", "circo", "cisne", "clareza", "clima", "clube", "cobertor",
    "cobre", "coco", "coelho", "cofre", "colar", "colcha", "colete", "colher",
    "colina", "coluna", "cometa", "comida", "compota", "concha", "cone", "conforto",
    "conta", "convite", "copo", "coral", "corda", "coroa", "corredor", "correio",
    "cortina", "costa", "cotovelo", "couro", "couve", "cravo", "creme", "cristal",
    "croche", "cubo", "cultura", "cupula", "curva", "dado", "dalia", "danca",
    "data", "degrau", "desenho", "deserto", "detalhe", "dia", "dialogo", "diario",
    "disco", "doca", "doce", "domingo", "dourado", "duna", "eco", "edicao",
    "editora", "efeito", "eixo", "elmo", "embate", "emblema", "emenda", "empada",
    "encanto", "enfeite", "engate", "enigma", "ensaio", "entrada", "envelope", "enxada",
    "epoca", "equipe", "erva", "escada", "escala", "escola", "escova", "esfera",
    "esmalte", "espaco", "espelho", "espiga", "esponja", "espuma", "estacao", "estante",
    "esteira", "estilo", "estojo", "estrada", "estrela", "estudo", "etapa", "etiqueta",
    "evento", "exame", "exemplo", "fabrica", "fachada", "faisca", "faixa", "fardo",
]

assert len(VOCABULARIO_COBERTURA_256) == 256, "Léxico de cobertura deve conter exatamente 256 termos."
assert len(set(VOCABULARIO_COBERTURA_256)) == 256, "Léxico de cobertura contém duplicados!"
assert set(VOCABULARIO).isdisjoint(set(VOCABULARIO_COBERTURA_256)), "Léxico de cobertura deve ser disjunto do tático!"


# ==============================================================================
# NÚCLEO DO ALGORITMO CHACHA20 (RFC 8439 ESPECIFICAÇÃO)
# ==============================================================================

def rotl32(v: int, c: int) -> int:
    """Rotação circular à esquerda de 32 bits."""
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def quarter_round(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    """Operação elementar ARX (Add, Rotate, XOR) do ChaCha20."""
    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = rotl32(d, 16)

    c = (c + d) & 0xFFFFFFFF
    b ^= c
    b = rotl32(b, 12)

    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = rotl32(d, 8)

    c = (c + d) & 0xFFFFFFFF
    b ^= c
    b = rotl32(b, 7)

    return a, b, c, d


def chacha20_block(chave_bytes: list[int], contador: int, nonce_bytes: list[int]) -> list[int]:
    """
    Gera um bloco de 64 bytes pseudoaleatórios usando a matriz 4x4 do ChaCha20:
    - 4 palavras constantes: "expand 32-byte k"
    - 8 palavras de chave (256 bits)
    - 1 palavra de contador de bloco (32 bits)
    - 3 palavras de Nonce (96 bits)
    """
    if len(chave_bytes) != 32:
        raise ValueError("Chave ChaCha20 deve ter exatamente 32 bytes (256 bits).")
    if len(nonce_bytes) != 12:
        raise ValueError("Nonce ChaCha20 deve ter exatamente 12 bytes (96 bits).")
    if not (0 <= contador <= 0xFFFFFFFF):
        raise OverflowError("Contador de bloco ChaCha20 fora do intervalo uint32 [0, 2^32 - 1].")

    constantes = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]

    chave_words = [
        chave_bytes[i] | (chave_bytes[i + 1] << 8) | (chave_bytes[i + 2] << 16) | (chave_bytes[i + 3] << 24)
        for i in range(0, 32, 4)
    ]

    nonce_words = [
        nonce_bytes[i] | (nonce_bytes[i + 1] << 8) | (nonce_bytes[i + 2] << 16) | (nonce_bytes[i + 3] << 24)
        for i in range(0, 12, 4)
    ]

    estado = constantes + chave_words + [contador] + nonce_words
    trabalho = list(estado)

    # 10 iterações duplas = 20 rondas ChaCha
    for _ in range(10):
        # Rondas de Colunas
        trabalho[0], trabalho[4], trabalho[8],  trabalho[12] = quarter_round(trabalho[0], trabalho[4], trabalho[8],  trabalho[12])
        trabalho[1], trabalho[5], trabalho[9],  trabalho[13] = quarter_round(trabalho[1], trabalho[5], trabalho[9],  trabalho[13])
        trabalho[2], trabalho[6], trabalho[10], trabalho[14] = quarter_round(trabalho[2], trabalho[6], trabalho[10], trabalho[14])
        trabalho[3], trabalho[7], trabalho[11], trabalho[15] = quarter_round(trabalho[3], trabalho[7], trabalho[11], trabalho[15])

        # Rondas Diagonais
        trabalho[0], trabalho[5], trabalho[10], trabalho[15] = quarter_round(trabalho[0], trabalho[5], trabalho[10], trabalho[15])
        trabalho[1], trabalho[6], trabalho[11], trabalho[12] = quarter_round(trabalho[1], trabalho[6], trabalho[11], trabalho[12])
        trabalho[2], trabalho[7], trabalho[8],  trabalho[13] = quarter_round(trabalho[2], trabalho[7], trabalho[8],  trabalho[13])
        trabalho[3], trabalho[4], trabalho[9],  trabalho[14] = quarter_round(trabalho[3], trabalho[4], trabalho[9],  trabalho[14])

    bloco_saida_bytes = []
    for i in range(16):
        soma = (trabalho[i] + estado[i]) & 0xFFFFFFFF
        bloco_saida_bytes.extend([
            soma & 0xFF,
            (soma >> 8) & 0xFF,
            (soma >> 16) & 0xFF,
            (soma >> 24) & 0xFF,
        ])

    return bloco_saida_bytes


def gerar_nonce_96bits() -> list[int]:
    """Gera um Nonce fresco de 96 bits (12 bytes) via CSPRNG do sistema operativo (os.urandom)."""
    return list(os.urandom(12))


# ==============================================================================
# NORMALIZAÇÃO E VETORES OFICIAIS IETF RFC 8439 (VALIDAÇÃO INTEGRAL 100%)
# ==============================================================================

def normalizar_chave_256bits(chave_64_hex: str) -> list[int]:
    """Converte string hexadecimal de 64 caracteres em 32 bytes (256 bits) bijetivamente."""
    chave_limpa = chave_64_hex.strip()
    if len(chave_limpa) != 64:
        raise ValueError("A chave deve conter exatamente 64 caracteres hexadecimais (256 bits).")
    try:
        return [int(chave_limpa[i:i + 2], 16) for i in range(0, 64, 2)]
    except ValueError as exc:
        raise ValueError("A chave contém caracteres não-hexadecimais.") from exc


def validar_vetor_rfc8439() -> bool:
    """
    Valida TODOS os 64 bytes do motor ChaCha20 contra o Vetor Oficial RFC 8439 (Secção 2.3.2).
    """
    chave_rfc = list(range(32))  # 00:01:02:...:1f
    contador_rfc = 1
    nonce_rfc = [0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x00, 0x00]
    bloco_esperado_64b = [
        0x10, 0xF1, 0xE7, 0xE4, 0xD1, 0x3B, 0x59, 0x15,
        0x50, 0x0F, 0xDD, 0x1F, 0xA3, 0x20, 0x71, 0xC4,
        0xC7, 0xD1, 0xF4, 0xC7, 0x33, 0xC0, 0x68, 0x03,
        0x04, 0x22, 0xAA, 0x9A, 0xC3, 0xD4, 0x6C, 0x4E,
        0xD2, 0x82, 0x64, 0x46, 0x07, 0x9F, 0xAA, 0x09,
        0x14, 0xC2, 0xD7, 0x05, 0xD9, 0x8B, 0x02, 0xA2,
        0xB5, 0x12, 0x9C, 0xD1, 0xDE, 0x16, 0x4E, 0xB9,
        0xCB, 0xD0, 0x83, 0xE8, 0xA2, 0x50, 0x3C, 0x4E,
    ]
    bloco = chacha20_block(chave_rfc, contador_rfc, nonce_rfc)
    return constant_time_compare(bloco, bloco_esperado_64b)


def validar_vetor_aead_rfc8439_secao282() -> bool:
    """
    Valida a construção AEAD ChaCha20-Poly1305 contra o Vetor Oficial RFC 8439 (Secção 2.8.2),
    verificando integralmente os 114 bytes de ciphertext e os 16 bytes da Tag Poly1305.
    """
    key = [0x80 + i for i in range(32)]
    nonce = [0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47]
    aad = [0x50, 0x51, 0x52, 0x53, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7]
    plaintext = list(
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    )

    ciphertext_esperado = [
        0xD3, 0x1A, 0x8D, 0x34, 0x64, 0x8E, 0x60, 0xDB, 0x7B, 0x86, 0xAF, 0xBC, 0x53, 0xEF, 0x7E, 0xC2,
        0xA4, 0xAD, 0xED, 0x51, 0x29, 0x6E, 0x08, 0xFE, 0xA9, 0xE2, 0xB5, 0xA7, 0x36, 0xEE, 0x62, 0xD6,
        0x3D, 0xBE, 0xA4, 0x5E, 0x8C, 0xA9, 0x67, 0x12, 0x82, 0xFA, 0xFB, 0x69, 0xDA, 0x92, 0x72, 0x8B,
        0x1A, 0x71, 0xDE, 0x0A, 0x9E, 0x06, 0x0B, 0x29, 0x05, 0xD6, 0xA5, 0xB6, 0x7E, 0xCD, 0x3B, 0x36,
        0x92, 0xDD, 0xBD, 0x7F, 0x2D, 0x77, 0x8B, 0x8C, 0x98, 0x03, 0xAE, 0xE3, 0x28, 0x09, 0x1B, 0x58,
        0xFA, 0xB3, 0x24, 0xE4, 0xFA, 0xD6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8B, 0x48, 0x31, 0xD7, 0xBC,
        0x3F, 0xF4, 0xDE, 0xF0, 0x8E, 0x4B, 0x7A, 0x9D, 0xE5, 0x76, 0xD2, 0x65, 0x86, 0xCE, 0xC6, 0x4B,
        0x61, 0x16,
    ]
    tag_esperada = [
        0x1A, 0xE1, 0x0B, 0x59, 0x4F, 0x09, 0xE2, 0x6A,
        0x7E, 0x90, 0x2E, 0xCB, 0xD0, 0x60, 0x06, 0x91,
    ]

    otk = chacha20_block(key, 0, nonce)[:32]
    keystream = []
    c = 1
    while len(keystream) < len(plaintext):
        keystream.extend(chacha20_block(key, c, nonce))
        c += 1
    ciphertext = [p ^ k for p, k in zip(plaintext, keystream[:len(plaintext)])]
    mac_data = construir_mac_data_rfc8439(aad, ciphertext)
    tag_calculada = poly1305_mac(mac_data, otk)

    return (
        constant_time_compare(ciphertext, ciphertext_esperado)
        and constant_time_compare(tag_calculada, tag_esperada)
    )


def derivar_chave_poly1305(chave_bytes: list[int], nonce_bytes: list[int]) -> list[int]:
    """Deriva chave descartável de 32 bytes para Poly1305 a partir do bloco 0 (RFC 8439 Sec. 2.6)."""
    return chacha20_block(chave_bytes, 0, nonce_bytes)[:32]


def derivar_deslocamentos_chacha20(
    chave_bytes: list[int],
    nonce_bytes: list[int],
    qtd: int,
    modulo: int,
    rejection_sampling: bool = True,
) -> list[int]:
    """
    Gera deslocamentos uniformes em Z_modulo consumindo blocos ChaCha20 (contador >= 1).
    Usa guarda de overflow uint32 e via rápida de 8 bits (1 byte/token, 64 tokens/bloco)
    sempre que modulo <= 256 e 256 % modulo == 0 (ex.: N=16, 64, 128, 256), eliminando
    desperdício de keystream e executando em tempo estritamente determinístico (Δp = 0.00).

    Para módulos arbitrários (ex.: N=20), amostra inteiros de 16 bits com rejection sampling
    ativo por omissão (descarta K_i >= 65536 - (65536 % modulo), p_reject < 0.031%).
    """
    if modulo < 2 or modulo > 65536:
        raise ValueError("Módulo do léxico deve estar no intervalo [2, 65536].")
    if qtd <= 0:
        return []

    # Via rápida 8-bit sem desperdício de keystream (1 byte/token = 64 tokens por bloco ChaCha20)
    if modulo <= 256 and (256 % modulo == 0):
        blocos_necessarios = (qtd + 63) // 64
        if blocos_necessarios > 0xFFFFFFFF:
            raise OverflowError("Limite de 2^32 - 1 blocos ChaCha20 excedido para o mesmo Nonce.")
        stream: list[int] = []
        for c in range(1, blocos_necessarios + 1):
            stream.extend(chacha20_block(chave_bytes, c, nonce_bytes))
        if modulo == 256:
            return stream[:qtd]
        mascara = modulo - 1
        return [b & mascara for b in stream[:qtd]]

    # Via genérica 16-bit com cursor O(1) e rejection sampling exato
    deslocamentos = []
    contador = 1
    bloco = []
    cursor = 0
    resto = 65536 % modulo
    usar_rejeicao = rejection_sampling and (resto != 0)
    limite_amostragem = 65536 - resto if usar_rejeicao else 65536

    while len(deslocamentos) < qtd:
        if cursor + 1 >= len(bloco):
            if contador > 0xFFFFFFFF:
                raise OverflowError("Limite de 2^32 - 1 blocos ChaCha20 excedido para o mesmo Nonce.")
            bloco = chacha20_block(chave_bytes, contador, nonce_bytes)
            contador += 1
            cursor = 0

        inteiro_16bits = (bloco[cursor] << 8) | bloco[cursor + 1]
        cursor += 2

        if usar_rejeicao and inteiro_16bits >= limite_amostragem:
            continue

        deslocamentos.append(inteiro_16bits % modulo)

    return deslocamentos


def normalizar_dados_associados(dados_associados: bytes | list[int] | str) -> list[int]:
    """Converte dados associados (str, bytes ou list[int]) em lista de bytes [0, 255]."""
    if isinstance(dados_associados, str):
        return list(dados_associados.encode("utf-8"))
    if isinstance(dados_associados, (bytes, bytearray)):
        return list(dados_associados)
    if isinstance(dados_associados, list):
        return [int(b) & 0xFF for b in dados_associados]
    return []


# ==============================================================================
# MOTOR GENÉRICO LEXICAL AEAD (SUPORTA N=256 ÓTIMO, N=20 LEGADO E PADDING)
# ==============================================================================

class LexicalAEAD:
    """
    Motor Lexical AEAD sobre anel modular Z_N com:
    - Suporte a léxico de cobertura benigno desacoplado do léxico operacional;
    - Serialização canónica estrita (rejeita overflow >= 2^96 e >= 2^128 -> zero maleabilidade);
    - Rejection sampling ativo por omissão para N não potência de 2;
    - Padding aleatório em buckets fixos (mitigação real de length fingerprinting);
    - Geração automática de Nonce CSPRNG via os.urandom(12).
    """

    def __init__(
        self,
        vocabulario_cobertura: list[str],
        vocabulario_operacional: list[str] | None = None,
    ):
        self.vocab_cobertura = list(vocabulario_cobertura)
        self.n = len(self.vocab_cobertura)
        if self.n < 2:
            raise ValueError("Vocabulário de cobertura deve conter pelo menos 2 termos.")
        if len(set(self.vocab_cobertura)) != self.n:
            raise ValueError("Vocabulário de cobertura contém termos duplicados.")

        self.cob_para_id = {w: i for i, w in enumerate(self.vocab_cobertura)}
        self.id_para_cob = {i: w for i, w in enumerate(self.vocab_cobertura)}

        if vocabulario_operacional is None:
            self.vocab_op = self.vocab_cobertura
        else:
            self.vocab_op = list(vocabulario_operacional)
            if len(self.vocab_op) > self.n:
                raise ValueError("Vocabulário operacional não pode exceder dimensão N do léxico de cobertura.")
            if len(set(self.vocab_op)) != len(self.vocab_op):
                raise ValueError("Vocabulário operacional contém termos duplicados.")

        self.op_para_id = {w: i for i, w in enumerate(self.vocab_op)}
        self.id_para_op = {i: w for i, w in enumerate(self.vocab_op)}

        self.len_nonce_tokens = math.ceil(96 / math.log2(self.n))
        self.len_tag_tokens = math.ceil(128 / math.log2(self.n))

    def _bytes_para_tokens(self, raw_bytes: list[int], num_tokens: int) -> list[str]:
        val = 0
        for i, b in enumerate(raw_bytes):
            val |= (b << (8 * i))
        tokens = []
        for _ in range(num_tokens):
            tokens.append(self.id_para_cob[val % self.n])
            val //= self.n
        return tokens

    def _tokens_para_bytes_canonico(self, tokens: list[str], num_bytes: int, expected_tokens: int, rotulo: str) -> list[int]:
        if len(tokens) != expected_tokens:
            raise ValueError(f"{rotulo} deve conter exatamente {expected_tokens} tokens.")
        val = 0
        for t in reversed(tokens):
            tok = t.strip().lower()
            if tok not in self.cob_para_id:
                raise ValueError(f"Token desconhecido '{tok}' em {rotulo}.")
            val = val * self.n + self.cob_para_id[tok]
        max_val = 1 << (8 * num_bytes)
        if val >= max_val:
            raise ValueError(
                f"Falha de Autenticação / Forma Não-Canónica: {rotulo} excede limite estrito de {8 * num_bytes} bits!"
            )
        return [(val >> (8 * i)) & 0xFF for i in range(num_bytes)]

    def nonce_para_tokens(self, nonce_12bytes: list[int]) -> list[str]:
        if len(nonce_12bytes) != 12:
            raise ValueError("Nonce deve conter exatamente 12 bytes (96 bits).")
        return self._bytes_para_tokens(nonce_12bytes, self.len_nonce_tokens)

    def tokens_para_nonce(self, tokens_preambulo: list[str]) -> list[int]:
        return self._tokens_para_bytes_canonico(tokens_preambulo, 12, self.len_nonce_tokens, "Preâmbulo de Nonce")

    def tag_para_tokens(self, tag_16bytes: list[int]) -> list[str]:
        if len(tag_16bytes) != 16:
            raise ValueError("Tag Poly1305 deve conter exatamente 16 bytes (128 bits).")
        return self._bytes_para_tokens(tag_16bytes, self.len_tag_tokens)

    def tokens_para_tag(self, tokens_tag: list[str]) -> list[int]:
        return self._tokens_para_bytes_canonico(tokens_tag, 16, self.len_tag_tokens, "Sufixo de Tag")

    def _random_cover_index(self) -> int:
        """Amostra índice uniforme em Z_N via CSPRNG os.urandom com rejection sampling exato."""
        limite = 65536 - (65536 % self.n)
        while True:
            b = os.urandom(2)
            v = (b[0] << 8) | b[1]
            if v < limite:
                return v % self.n

    def cifrar(
        self,
        mensagem: str,
        chave_64_hex: str,
        nonce_12bytes: list[int] | None = None,
        dados_associados: bytes | list[int] | str = b"",
        rejection_sampling: bool = True,
        pad_bucket: int | None = None,
    ) -> list[str]:
        """
        Cifra mensagem operacional sobre Z_N emitindo 100% termos do léxico de cobertura.
        Se nonce_12bytes=None, gera automaticamente nonce de 96 bits via os.urandom(12).
        Se pad_bucket for fornecido (ex.: 64, 128), adiciona cabeçalho cifrado de comprimento
        (2 tokens base-N) e padding CSPRNG até preencher exatamente pad_bucket tokens.
        """
        palavras = mensagem.strip().lower().split()
        chave_bytes = normalizar_chave_256bits(chave_64_hex)
        nonce = gerar_nonce_96bits() if nonce_12bytes is None else list(nonce_12bytes)
        if len(nonce) != 12:
            raise ValueError("Nonce deve conter exatamente 12 bytes (96 bits).")

        indices_plain = []
        for palavra in palavras:
            if palavra not in self.op_para_id:
                raise ValueError(f"Termo operacional '{palavra}' não existe no dicionário!")
            indices_plain.append(self.op_para_id[palavra])

        # Padding aleatório em buckets fixos (com cabeçalho cifrado de 2 tokens base-N)
        if pad_bucket is not None:
            capacidade_max = min(pad_bucket - 2, self.n * self.n - 1)
            if pad_bucket < 2 or len(indices_plain) > capacidade_max:
                raise ValueError(
                    f"Mensagem ({len(indices_plain)} tokens) excede capacidade útil do bucket ({capacidade_max})."
                )
            m_len = len(indices_plain)
            hdr = [m_len % self.n, m_len // self.n]
            pad_qtd = pad_bucket - 2 - m_len
            padding = [self._random_cover_index() for _ in range(pad_qtd)]
            indices_plain = hdr + indices_plain + padding

        deslocamentos = derivar_deslocamentos_chacha20(
            chave_bytes, nonce, len(indices_plain), self.n, rejection_sampling=rejection_sampling
        )
        tokens_cifrados = [
            self.id_para_cob[(idx_orig + deslocamentos[i]) % self.n]
            for i, idx_orig in enumerate(indices_plain)
        ]

        preambulo_nonce = self.nonce_para_tokens(nonce)

        # Autenticação Poly1305 AEAD (RFC 8439 Sec. 2.8) sobre AAD e corpo cifrado
        key_poly = derivar_chave_poly1305(chave_bytes, nonce)
        corpo_bytes = list(" ".join(tokens_cifrados).encode("utf-8"))
        aad_bytes = normalizar_dados_associados(dados_associados)
        mac_data = construir_mac_data_rfc8439(aad_bytes, corpo_bytes)
        tag_bytes = poly1305_mac(mac_data, key_poly)
        sufixo_tag = self.tag_para_tokens(tag_bytes)

        return preambulo_nonce + tokens_cifrados + sufixo_tag

    def decifrar(
        self,
        pacote_tokens: list[str],
        chave_64_hex: str,
        dados_associados: bytes | list[int] | str = b"",
        rejection_sampling: bool = True,
        pad_bucket: int | None = None,
    ) -> str:
        """
        Valida forma canónica de Nonce e Tag, verifica integridade Poly1305 em tempo constante
        e decifra a carga para o vocabulário operacional. Lança sempre ValueError em adulteração.
        """
        min_tokens = self.len_nonce_tokens + self.len_tag_tokens
        if len(pacote_tokens) < min_tokens:
            raise ValueError("Pacote inválido: tamanho menor que preâmbulo + tag.")

        tokens_nonce = pacote_tokens[:self.len_nonce_tokens]
        tokens_cifrados = [t.strip().lower() for t in pacote_tokens[self.len_nonce_tokens:-self.len_tag_tokens]]
        tokens_tag = pacote_tokens[-self.len_tag_tokens:]

        chave_bytes = normalizar_chave_256bits(chave_64_hex)
        nonce_bytes = self.tokens_para_nonce(tokens_nonce)
        tag_esperada = self.tokens_para_tag(tokens_tag)

        # 1. Verificação Estrita de Integridade Poly1305 antes de qualquer decifração
        key_poly = derivar_chave_poly1305(chave_bytes, nonce_bytes)
        corpo_bytes = list(" ".join(tokens_cifrados).encode("utf-8"))
        aad_bytes = normalizar_dados_associados(dados_associados)
        mac_data = construir_mac_data_rfc8439(aad_bytes, corpo_bytes)
        tag_calculada = poly1305_mac(mac_data, key_poly)

        if not constant_time_compare(tag_calculada, tag_esperada):
            raise ValueError("Falha de Autenticação Poly1305: Pacote ou AAD adulterado em trânsito!")

        # 2. Decifração modular Z_N
        deslocamentos = derivar_deslocamentos_chacha20(
            chave_bytes, nonce_bytes, len(tokens_cifrados), self.n, rejection_sampling=rejection_sampling
        )
        indices_rec = []
        for i, token in enumerate(tokens_cifrados):
            if token not in self.cob_para_id:
                raise ValueError(f"Termo cifrado '{token}' desconhecido no léxico de cobertura!")
            idx_cif = self.cob_para_id[token]
            indices_rec.append((idx_cif - deslocamentos[i]) % self.n)

        # 3. Remoção de bucket padding autenticado (se ativo)
        if pad_bucket is not None:
            if len(indices_rec) != pad_bucket or pad_bucket < 2:
                raise ValueError("Tamanho do pacote não corresponde ao bucket de padding esperado.")
            m_len = indices_rec[0] + indices_rec[1] * self.n
            if m_len > pad_bucket - 2:
                raise ValueError("Cabeçalho de comprimento de padding inválido.")
            indices_rec = indices_rec[2:2 + m_len]

        palavras_recuperadas = []
        for idx_orig in indices_rec:
            if idx_orig not in self.id_para_op:
                raise ValueError(f"Índice decifrado {idx_orig} fora do vocabulário operacional!")
            palavras_recuperadas.append(self.id_para_op[idx_orig])

        return " ".join(palavras_recuperadas)


# Instâncias prontas a usar:
# - MOTOR_OPTIMO_256: Léxico de cobertura benigno N=256 (0 viés MSB, 0 viés mod, 0 palavras militares no fio)
# - MOTOR_TATICO_20:  Perfil legado N=20 (com rejection sampling e validação canónica estrita)
MOTOR_OPTIMO_256 = LexicalAEAD(VOCABULARIO_COBERTURA_256, vocabulario_operacional=VOCABULARIO)
MOTOR_COBERTURA_256 = LexicalAEAD(VOCABULARIO_COBERTURA_256)
MOTOR_TATICO_20 = LexicalAEAD(VOCABULARIO)

LEN_NONCE_TOKENS = MOTOR_TATICO_20.len_nonce_tokens  # 23 (N=20)
LEN_TAG_TOKENS = MOTOR_TATICO_20.len_tag_tokens      # 30 (N=20)


# ==============================================================================
# BASELINE COMPARATIVO: RFC 8439 BINÁRIO PADRÃO + CODIFICAÇÃO LEXICAL BASE-256
# ==============================================================================

def cifrar_rfc8439_base256(
    mensagem_utf8: str,
    chave_64_hex: str,
    nonce_12bytes: list[int] | None = None,
    dados_associados: bytes | list[int] | str = b"",
) -> list[str]:
    """
    Baseline canónico: RFC 8439 ChaCha20-Poly1305 binário padrão sobre UTF-8,
    seguido de codificação bijetiva 1 byte -> 1 palavra do léxico de cobertura (N=256).
    """
    chave_bytes = normalizar_chave_256bits(chave_64_hex)
    nonce = gerar_nonce_96bits() if nonce_12bytes is None else list(nonce_12bytes)
    plain_bytes = list(mensagem_utf8.encode("utf-8"))

    keystream = []
    c = 1
    while len(keystream) < len(plain_bytes):
        keystream.extend(chacha20_block(chave_bytes, c, nonce))
        c += 1
    ct_bytes = [p ^ k for p, k in zip(plain_bytes, keystream[:len(plain_bytes)])]

    otk = derivar_chave_poly1305(chave_bytes, nonce)
    aad_bytes = normalizar_dados_associados(dados_associados)
    mac_data = construir_mac_data_rfc8439(aad_bytes, ct_bytes)
    tag_bytes = poly1305_mac(mac_data, otk)

    envelope_bytes = nonce + ct_bytes + tag_bytes
    return [VOCABULARIO_COBERTURA_256[b] for b in envelope_bytes]


def decifrar_rfc8439_base256(
    pacote_tokens: list[str],
    chave_64_hex: str,
    dados_associados: bytes | list[int] | str = b"",
) -> str:
    """Decifra baseline RFC 8439 padrão codificado em léxico de cobertura (N=256)."""
    if len(pacote_tokens) < 28:
        raise ValueError("Pacote RFC 8439 Base-256 inválido (< 28 tokens).")
    cob_map = MOTOR_COBERTURA_256.cob_para_id
    try:
        raw = [cob_map[t.strip().lower()] for t in pacote_tokens]
    except KeyError as exc:
        raise ValueError(f"Token desconhecido no pacote RFC 8439 Base-256: {exc}") from exc

    nonce = raw[:12]
    ct_bytes = raw[12:-16]
    tag_esp = raw[-16:]

    chave_bytes = normalizar_chave_256bits(chave_64_hex)
    otk = derivar_chave_poly1305(chave_bytes, nonce)
    aad_bytes = normalizar_dados_associados(dados_associados)
    mac_data = construir_mac_data_rfc8439(aad_bytes, ct_bytes)
    tag_calc = poly1305_mac(mac_data, otk)

    if not constant_time_compare(tag_calc, tag_esp):
        raise ValueError("Falha de Autenticação Poly1305 no baseline RFC 8439 Base-256!")

    keystream = []
    c = 1
    while len(keystream) < len(ct_bytes):
        keystream.extend(chacha20_block(chave_bytes, c, nonce))
        c += 1
    plain_bytes = bytes([ct ^ k for ct, k in zip(ct_bytes, keystream[:len(ct_bytes)])])
    return plain_bytes.decode("utf-8")


# ==============================================================================
# WRAPPERS DE COMPATIBILIDADE (PERFIL N=20 E PERFIL ÓTIMO N=256)
# ==============================================================================

def nonce_para_tokens(nonce_12bytes: list[int]) -> list[str]:
    return MOTOR_TATICO_20.nonce_para_tokens(nonce_12bytes)


def tokens_para_nonce(tokens_preambulo: list[str]) -> list[int]:
    return MOTOR_TATICO_20.tokens_para_nonce(tokens_preambulo)


def tag_para_tokens(tag_16bytes: list[int]) -> list[str]:
    return MOTOR_TATICO_20.tag_para_tokens(tag_16bytes)


def tokens_para_tag(tokens_tag: list[str]) -> list[int]:
    return MOTOR_TATICO_20.tokens_para_tag(tokens_tag)


def cifrar_com_chacha20(
    mensagem: str,
    chave_64_hex: str,
    nonce_12bytes: list[int],
    rejection_sampling: bool = True,
) -> list[str]:
    """Cifra modular sobre Z_20 sem camada AEAD (para benchmark comparativo de fluxo)."""
    palavras = mensagem.strip().lower().split()
    chave_bytes = normalizar_chave_256bits(chave_64_hex)
    deslocamentos = derivar_deslocamentos_chacha20(
        chave_bytes, nonce_12bytes, len(palavras), N, rejection_sampling=rejection_sampling
    )
    resultado = []
    for i, palavra in enumerate(palavras):
        if palavra not in PALAVRA_PARA_ID:
            raise ValueError(f"Termo '{palavra}' não existe no dicionário!")
        idx_cifrado = (PALAVRA_PARA_ID[palavra] + deslocamentos[i]) % N
        resultado.append(ID_PARA_PALAVRA[idx_cifrado])
    return resultado


def decifrar_com_chacha20(
    termos_cifrados: list[str],
    chave_64_hex: str,
    nonce_12bytes: list[int],
    rejection_sampling: bool = True,
) -> str:
    """Decifra modular sobre Z_20 sem camada AEAD."""
    chave_bytes = normalizar_chave_256bits(chave_64_hex)
    deslocamentos = derivar_deslocamentos_chacha20(
        chave_bytes, nonce_12bytes, len(termos_cifrados), N, rejection_sampling=rejection_sampling
    )
    palavras_recuperadas = []
    for i, token in enumerate(termos_cifrados):
        tok = token.strip().lower()
        if tok not in PALAVRA_PARA_ID:
            raise ValueError(f"Termo cifrado '{tok}' desconhecido no dicionário!")
        idx_original = (PALAVRA_PARA_ID[tok] - deslocamentos[i]) % N
        palavras_recuperadas.append(ID_PARA_PALAVRA[idx_original])
    return " ".join(palavras_recuperadas)


def cifrar_aead_lexical(
    mensagem: str,
    chave_64_hex: str,
    nonce_12bytes: list[int] | None = None,
    dados_associados: bytes | list[int] | str = b"",
    rejection_sampling: bool = True,
    pad_bucket: int | None = None,
) -> list[str]:
    """Perfil ótimo recomendado: Lexical AEAD sobre Z_256 com léxico de cobertura benigno."""
    return MOTOR_OPTIMO_256.cifrar(
        mensagem, chave_64_hex, nonce_12bytes, dados_associados, rejection_sampling, pad_bucket
    )


def decifrar_aead_lexical(
    pacote_tokens: list[str],
    chave_64_hex: str,
    dados_associados: bytes | list[int] | str = b"",
    rejection_sampling: bool = True,
    pad_bucket: int | None = None,
) -> str:
    """Decifração do perfil ótimo recomendado: Lexical AEAD sobre Z_256."""
    return MOTOR_OPTIMO_256.decifrar(
        pacote_tokens, chave_64_hex, dados_associados, rejection_sampling, pad_bucket
    )


# ==============================================================================
# SUITE DE VALIDAÇÃO UNITÁRIA E PROVA ANTI-MALEABILIDADE
# ==============================================================================
def executar_testes():
    print("=" * 78)
    print("   LEXICAL AEAD (CHACHA20-POLY1305 RFC 8439) EM PYTHON PURO (ZERO LIBS 3os)")
    print("=" * 78)

    chave_64 = "47a5ccbb7e65e5f6074670814f33529a660c05903d66839e35d8f512d46b94b1"
    mensagem = "atacar base amanha esperar reforcos norte atacar base"
    nonce_sessao_1 = [23, 25, 43, 77, 99, 12, 84, 53, 21, 65, 33, 90]

    print(f"[*] Mensagem Operacional : {mensagem}")
    print(f"[*] Chave (256-bit hex)  : {chave_64}")

    # TESTE 0: Conformidade Integral (100% dos bytes) com Vetores Oficiais RFC 8439
    assert validar_vetor_rfc8439(), "Falha Sec. 2.3.2 (64 bytes completos)!"
    assert validar_vetor_poly1305_rfc8439(), "Falha Sec. 2.5.2 (Poly1305)!"
    assert validar_vetor_aead_rfc8439_secao282(), "Falha Sec. 2.8.2 (AEAD completo: 114B ct + 16B tag)!"
    print("\n -> TESTE 0 PASSOU: Conformidade integral 100% bit-a-bit RFC 8439 (Sec. 2.3.2 [64B], 2.5.2, 2.8.2 [114B+16B]).")

    # TESTE 1: Cifragem Modular Z_20 com Rejection Sampling ativo por omissão
    cif_20 = cifrar_com_chacha20(mensagem, chave_64, nonce_sessao_1)
    assert decifrar_com_chacha20(cif_20, chave_64, nonce_sessao_1) == mensagem
    print(" -> TESTE 1 PASSOU: Reversibilidade modular Z_20 com Rejection Sampling (Δp = 0.00).")

    # TESTE 2: Lexical AEAD Ótimo N=256 (Léxico Benigno Desacoplado + Nonce CSPRNG Automático)
    pacote_256 = cifrar_aead_lexical(mensagem, chave_64)  # nonce=None -> os.urandom(12)
    assert len(pacote_256) == 12 + 8 + 16  # 36 palavras benignas!
    assert set(pacote_256).isdisjoint(set(VOCABULARIO)), "Palavra militar vazou para o fio!"
    assert decifrar_aead_lexical(pacote_256, chave_64) == mensagem
    print(f"\n[+] Pacote Lexical AEAD Z_256 ({len(pacote_256)} palavras 100% benignas, 0 termos militares):")
    print(f"    - Preâmbulo Nonce (12) : {' '.join(pacote_256[:12])}")
    print(f"    - Carga Cifrada   (8)  : {' '.join(pacote_256[12:-16])}")
    print(f"    - Tag Poly1305    (16) : {' '.join(pacote_256[-16:])}")
    print(" -> TESTE 2 PASSOU: Léxico de cobertura benigno desacoplado e nonce CSPRNG validados.")

    # TESTE 3: AAD (RFC 8439 Sec. 2.8) + Deteção de Adulteração em Payload, Nonce, Tag e AAD
    aad = "sessao=hq-01;seq=42"
    pkt_aad = cifrar_aead_lexical(mensagem, chave_64, nonce_sessao_1, dados_associados=aad)
    assert decifrar_aead_lexical(pkt_aad, chave_64, dados_associados=aad) == mensagem

    for desc, mut_idx, mut_aad in [
        ("ciphertext", 14, aad),
        ("nonce preamble", 3, aad),
        ("poly1305 tag", len(pkt_aad) - 2, aad),
        ("associated data", None, "sessao=hq-01;seq=99"),
    ]:
        copia = list(pkt_aad)
        if mut_idx is not None:
            copia[mut_idx] = "zebra_invalida" if desc == "oov" else (
                "abacate" if copia[mut_idx] != "abacate" else "abelha"
            )
        rejeitado = False
        try:
            decifrar_aead_lexical(copia, chave_64, dados_associados=mut_aad)
        except ValueError:
            rejeitado = True
        assert rejeitado, f"Falha anti-tamper em {desc}!"
    print(" -> TESTE 3 PASSOU: 100% rejeição de adulteração em ciphertext, nonce, tag e AAD.")

    # TESTE 4: Prova Anti-Maleabilidade Não-Canónica em N=20 (Rejeita +2^96, +2^128 e OOV -> ValueError)
    pkt_20 = MOTOR_TATICO_20.cifrar(mensagem, chave_64, nonce_sessao_1)
    assert MOTOR_TATICO_20.decifrar(pkt_20, chave_64) == mensagem

    # 4a. Forjar preâmbulo não-canónico: val + 2^96
    val_n = sum(b << (8 * i) for i, b in enumerate(nonce_sessao_1)) + (1 << 96)
    toks_n_forged = []
    tmp = val_n
    for _ in range(MOTOR_TATICO_20.len_nonce_tokens):
        toks_n_forged.append(ID_PARA_PALAVRA[tmp % 20])
        tmp //= 20
    forged_nonce_pkt = toks_n_forged + pkt_20[23:]

    # 4b. Forjar tag não-canónica: val_tag + 2^128
    tag_raw = MOTOR_TATICO_20.tokens_para_tag(pkt_20[-30:])
    val_t = sum(b << (8 * i) for i, b in enumerate(tag_raw)) + (1 << 128)
    toks_t_forged = []
    tmp = val_t
    for _ in range(MOTOR_TATICO_20.len_tag_tokens):
        toks_t_forged.append(ID_PARA_PALAVRA[tmp % 20])
        tmp //= 20
    forged_tag_pkt = pkt_20[:-30] + toks_t_forged

    # 4c. Token fora do vocabulário (deve lançar ValueError, nunca KeyError)
    oov_pkt = list(pkt_20)
    oov_pkt[0] = "palavra_inexistente"

    for nome_ataque, pkt_ataque in [
        ("nonce +2^96 overflow", forged_nonce_pkt),
        ("tag +2^128 overflow", forged_tag_pkt),
        ("out-of-vocabulary injection", oov_pkt),
    ]:
        ok_rej = False
        try:
            MOTOR_TATICO_20.decifrar(pkt_ataque, chave_64)
        except ValueError:
            ok_rej = True
        assert ok_rej, f"Vulnerabilidade de maleabilidade em {nome_ataque}!"
    print(" -> TESTE 4 PASSOU: Maleabilidade não-canónica (+2^96, +2^128) e OOV 100% bloqueadas em Z_20.")

    # TESTE 5: Randomized Bucket Padding (Mitigação Real de Length Fingerprinting)
    pkt_curto = cifrar_aead_lexical("atacar norte", chave_64, pad_bucket=64)
    pkt_longo = cifrar_aead_lexical(mensagem, chave_64, pad_bucket=64)
    assert len(pkt_curto) == len(pkt_longo) == 12 + 64 + 16  # 92 tokens idênticos!
    assert decifrar_aead_lexical(pkt_curto, chave_64, pad_bucket=64) == "atacar norte"
    assert decifrar_aead_lexical(pkt_longo, chave_64, pad_bucket=64) == mensagem
    print(f" -> TESTE 5 PASSOU: Bucket Padding (B=64) uniformizou 2 e 8 palavras para exatamente {len(pkt_curto)} tokens.")

    # TESTE 6: Baseline RFC 8439 Padrão + Codificação Base-256
    pkt_rfc_b256 = cifrar_rfc8439_base256(mensagem, chave_64, nonce_sessao_1, dados_associados=aad)
    assert decifrar_rfc8439_base256(pkt_rfc_b256, chave_64, dados_associados=aad) == mensagem
    reducao_pct = (1.0 - (len(pkt_aad) / len(pkt_rfc_b256))) * 100.0
    print(f" -> TESTE 6 PASSOU: Baseline RFC 8439+Base256 ({len(pkt_rfc_b256)} tokens) vs Lexical AEAD Z_256 ({len(pkt_aad)} tokens -> -{reducao_pct:.1f}% tokens).")

    print("\n[OK] Todos os 7 testes unitários e provas criptográficas passaram com 100% de sucesso.")


if __name__ == "__main__":
    executar_testes()
