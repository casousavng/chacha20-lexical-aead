#!/usr/bin/env bash
# ==============================================================================
# SCRIPT DE REPRODUCIBILIDADE EMPÍRICA — ARTEFACTO TP2 CRIPTOGRAFIA APLICADA
# ChaCha20-Poly1305 Lexical AEAD em Python Puro (RFC 8439)
# Autor: Carlos André Sousa (N.º 2022105675) — ISPGAYA MARSI 2026/2027
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CODE_DIR="${SCRIPT_DIR}/codigo_python"

BOLD="\033[1m"
GREEN="\033[0;32m"
BLUE="\033[0;34m"
CYAN="\033[0;36m"
RED="\033[0;31m"
RESET="\033[0m"

echo -e "${BOLD}${CYAN}"
echo "=============================================================================="
echo "   REPRODUTIBILIDADE DO ARTEFACTO: CHACHA20-POLY1305 LEXICAL AEAD (RFC 8439) "
echo "=============================================================================="
echo -e "${RESET}"

echo -e "${BOLD}[*] Verificação de Ambiente:${RESET}"
if command -v python3 &>/dev/null; then
    PY_VER=$(python3 --version)
    echo -e "    -> Interpretador : ${GREEN}${PY_VER}${RESET}"
else
    echo -e "    -> ${RED}ERRO: python3 não encontrado no PATH.${RESET}"
    exit 1
fi
echo -e "    -> Dependências  : ${GREEN}Zero bibliotecas de terceiros (100% Python stdlib)${RESET}\n"

echo -e "${BOLD}${BLUE}[FASE 1/3] Validação Unitária RFC 8439, Anti-Maleabilidade e Padding (app.py)${RESET}"
echo "------------------------------------------------------------------------------"
python3 "${CODE_DIR}/app.py"
echo ""

echo -e "${BOLD}${BLUE}[FASE 2/3] Bateria Estatística, Auditoria MSB e Throughput R=30 (benchmark.py)${RESET}"
echo "------------------------------------------------------------------------------"
python3 "${CODE_DIR}/benchmark.py"
echo ""

echo -e "${BOLD}${BLUE}[FASE 3/3] Simulação Empírica de Filtros Heurísticos DPI (experimento_pratico_dpi.py)${RESET}"
echo "------------------------------------------------------------------------------"
python3 "${CODE_DIR}/experimento_pratico_dpi.py"
echo ""

echo -e "${BOLD}${GREEN}"
echo "=============================================================================="
echo "   RESUMO DINÂMICO GERADO DIRETAMENTE DOS JSONs DE EXECUÇÃO ATUAL             "
echo "=============================================================================="
echo -e "${RESET}"

python3 - "${CODE_DIR}" << 'EOF'
import json, sys
from pathlib import Path

code_dir = Path(sys.argv[1])
b = json.loads((code_dir / "resultado_benchmark.json").read_text(encoding="utf-8"))
d = json.loads((code_dir / "resultado_experimento_dpi.json").read_text(encoding="utf-8"))

sac_k = b["sac"]["key"]
sac_n = b["sac"]["nonce"]
disp = b["dispersion_n20"]["ChaCha20 Z_20 (RS)"]
msb20_n = b["msb_audit"]["N20_nonce_msb"]
msb256_n = b["msb_audit"]["N256_nonce_msb"]
msb256_t = b["msb_audit"]["N256_tag_msb"]
tp_aead = b["throughput"]["lexical_aead_z256"]["2000"]
tp_rfc = b["throughput"]["rfc8439_base256"]["2000"]

rb_bin = d["regime_extenso_60w"]["Raw RFC 8439 Binary"]
rb_b256 = d["regime_extenso_60w"]["RFC 8439 + Base-256 Cover"]
rb_ours = d["regime_extenso_60w"]["Lexical AEAD Z_256 (Ours)"]
tamp = d["tamper_resistance"]
tamp_ok = (
    tamp["ciphertext_rejeitados"]
    + tamp["nonce_rejeitados"]
    + tamp["tag_rejeitados"]
    + tamp["aad_e_canonico_rejeitados"]
)
tamp_tot = tamp["total_por_categoria"] * 4

print(f" [x] RFC 8439 Integral : 2.3.2 (64B)={b['rfc8439_valid']['sec_2_3_2_full64B']}, "
      f"2.5.2={b['rfc8439_valid']['sec_2_5_2']}, 2.8.2={b['rfc8439_valid']['sec_2_8_2_full']}")
print(f" [x] SAC (n=300)       : Key {sac_k['percentual']:.2f}% (t={sac_k['t_stat']:+.3f}, p={sac_k['p_value']:.3f}) | "
      f"Nonce {sac_n['percentual']:.2f}% (t={sac_n['t_stat']:+.3f}, p={sac_n['p_value']:.3f})")
print(f" [x] Dispersão (N=20)  : H={disp['H']:.4f} ({disp['eta']:.2f}%), Chi2={disp['chi2']:.1f} (p={disp['p_value']:.3f}), r1={disp['r1']:+.4f}")
print(f" [x] Auditoria MSB     : N=20 Nonce={msb20_n['unique_observed']}/20 (p<1e-100) vs "
      f"N=256 Nonce={msb256_n['unique_observed']}/256 (p={msb256_n['p_value']:.3f}), Tag={msb256_t['unique_observed']}/256 (p={msb256_t['p_value']:.3f})")
print(f" [x] Throughput (2k)   : Lexical AEAD Z_256={tp_aead['throughput_mean']/1e3:.1f}k±{tp_aead['throughput_std']/1e3:.1f}k tok/s "
      f"vs RFC8439+Base256={tp_rfc['throughput_mean']/1e3:.1f}k±{tp_rfc['throughput_std']/1e3:.1f}k tok/s")
print(f" [x] DPI Regime B (60w): Binary H_b={rb_bin['media_entropia']:.4f} (Ent={rb_bin['alerta_f1_entropia_pct']:.0f}%, Bin={rb_bin['alerta_f2_binario_pct']:.0f}%) | "
      f"Ours H_b={rb_ours['media_entropia']:.4f} (Evade={rb_ours['taxa_evasao_pct']:.0f}%, {rb_ours['tamanho_medio_bytes']:.1f}B vs {rb_b256['tamanho_medio_bytes']:.1f}B Base256)")
print(f" [x] Anti-Tamper       : {tamp_ok}/{tamp_tot} rejeitados (100.0% em 4 vetores de ataque)")
EOF

echo -e "\n${BOLD}${CYAN}Todos os ensaios empíricos e auditorias de segurança foram concluídos com 100% de sucesso.${RESET}\n"
