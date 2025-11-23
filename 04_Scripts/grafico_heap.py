# grafico_heap_por_iteracao.py
# Barras agrupadas (128/192/256 × ML-KEM/ECDH/RSA), eixo Y linear (bytes).
# TXT: "Rótulo: valor_em_bytes" (aceita vírgula decimal; "NA" pula; "/ ..." é ignorado).
# RSA-15360: se ausente, estima por ajuste linear em função do tamanho da chave (bits),
# e desenha uma ghostbar (faixa ±25% em torno do valor estimado).

import sys, math
from pathlib import Path
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle
from matplotlib.ticker import MultipleLocator

# ----- Config -----
COLORS = {"ML-KEM": "#1f77b4", "ECDH": "#ff7f0e", "RSA": "#9467bd"}
BAR_WIDTH = 0.25
ESTIMATE_PRESENTATION = "ghostbar"   # "ghostbar" ou "callout"
SHOW_CENTRAL_MARK = True             # traço pontilhado dentro da ghostbar
GHOST_PCT_BAND = 0.25                # ±25% ao redor da estimativa (heap pode variar mais)
TOP_LABELS = True                    # rótulo com o valor exato no topo das barras

CALLOUT_BOX_KW = dict(
    boxstyle="round,pad=0.3", facecolor="#ede1ff",
    alpha=0.6, edgecolor="#6b4ca5", linewidth=1.0
)

def _num(s: str):
    s = s.strip()
    if s.upper() in {"NA", "N/A", ""}: return None
    s = s.replace(",", ".")
    try:
        return float(s)
    except:
        return None

def normalize_label(lbl: str) -> str:
    x = lbl.strip().lower()
    x = x.replace(" ", "").replace("_", "").replace("—", "-").replace("–", "-")
    x = x.replace("crystal-kybers", "ml-kem").replace("crystalkybers", "ml-kem").replace("kyber", "ml-kem")
    return x

def parse_line(line: str):
    if ":" not in line:
        return None
    k, rest = line.split(":", 1)
    lbl = normalize_label(k)
    # aceita "valor / qualquer_coisa", mas usa só o primeiro número
    first = rest.split("/")[0].strip()
    v_bytes = _num(first)
    if v_bytes is not None and v_bytes <= 0:
        v_bytes = None
    return (lbl, v_bytes)

def compute_rsa15360_heap_band(h3072, h7680, pct=GHOST_PCT_BAND):
    """
    Estima heap para 15360 por ajuste linear em função de nbits:
      h(n) ≈ a + b*n   usando (n1=3072, h1) e (n2=7680, h2)
    Retorna (low, cent, high, slope_b).
    """
    if h3072 is None or h7680 is None or h3072 <= 0 or h7680 <= 0:
        return None
    n1, n2, n3 = 3072, 7680, 15360
    b = (h7680 - h3072) / (n2 - n1)
    a = h3072 - b * n1
    h15360 = a + b * n3
    low  = max(0.0, h15360 * (1.0 - pct))
    high = h15360 * (1.0 + pct)
    return (low, h15360, high, b)

def fmt_bytes_int(x: float) -> str:
    # 13.616, 27.760 etc. (ponto como separador de milhar)
    s = f"{int(round(x)):,}"
    return s.replace(",", ".")

def main():
    if len(sys.argv) < 2:
        print("Uso: python grafico_heap_por_iteracao.py <arquivo_txt>")
        sys.exit(1)

    txt_path = Path(sys.argv[1])
    lines = txt_path.read_text(encoding="utf-8").splitlines()

    mapping = {
        # ML-KEM
        "ml-kem-512": ("ML-KEM","128"), "mlkem-512": ("ML-KEM","128"), "kyber-512": ("ML-KEM","128"),
        "ml-kem-768": ("ML-KEM","192"), "mlkem-768": ("ML-KEM","192"), "kyber-768": ("ML-KEM","192"),
        "ml-kem-1024":("ML-KEM","256"), "mlkem-1024":("ML-KEM","256"), "kyber-1024":("ML-KEM","256"),
        # ECDH
        "p-256": ("ECDH","128"), "p256": ("ECDH","128"), "ecdh-p256": ("ECDH","128"),
        "p-384": ("ECDH","192"), "p384": ("ECDH","192"), "ecdh-p384": ("ECDH","192"),
        "p-521": ("ECDH","256"), "p521": ("ECDH","256"), "ecdh-p521": ("ECDH","256"),
        # RSA
        "rsa-3072": ("RSA","128"), "rsa3072": ("RSA","128"),
        "rsa-7680": ("RSA","192"), "rsa7680": ("RSA","192"),
        "rsa-15360":("RSA","256"), "rsa15360":("RSA","256"),
    }

    groups, algos = ["128","192","256"], ["ML-KEM","ECDH","RSA"]
    data = {g: {a: {"v": None} for a in algos} for g in groups}

    for ln in lines:
        parsed = parse_line(ln)
        if parsed:
            k, v_bytes = parsed
            if k in mapping:
                a, sec = mapping[k]
                data[sec][a] = {"v": v_bytes}

    # Estimativa RSA-15360 somente se não houver valor medido
    rsa15360_measured = data["256"]["RSA"]["v"]
    rsa3072 = data["128"]["RSA"]["v"]
    rsa7680 = data["192"]["RSA"]["v"]
    band = None
    if rsa15360_measured is None:
        band = compute_rsa15360_heap_band(rsa3072, rsa7680)
        if band:
            low, cent, high, slope = band
            print(f"[Predição RSA-15360] slope={slope:.4f} B/bit; low={low:.3f} B; central={cent:.3f} B; high={high:.3f} B")
        else:
            print("[Predição RSA-15360] Não foi possível estimar (faltam 3072/7680).")

    # ----- Plot -----
    x = np.arange(len(groups))
    fig, ax = plt.subplots(figsize=(9.6, 5.4))

    # barras principais
    for i, algo in enumerate(algos):
        offset = (i - 1) * BAR_WIDTH
        color = COLORS[algo]
        for j, g in enumerate(groups):
            v = data[g][algo]["v"]
            if v is None:
                continue
            xc = x[j] + offset
            ax.bar(
                xc, v, BAR_WIDTH, color=color,
                edgecolor="#444", linewidth=0.5,
                label=algo if j == 0 else None, zorder=3
            )
            if TOP_LABELS:
                ax.text(xc, v, fmt_bytes_int(v), ha="center", va="bottom", fontsize=8)

    # eixo X/Y
    ax.set_xticks(x, [f"{g}-bits" for g in groups])
    ax.set_xlabel("Nível de segurança")
    ax.set_ylabel("Uso de heap (bytes)")

    # limites Y (considerando ghostbar se existir)
    y_vals = []
    for g in groups:
        for a in algos:
            v = data[g][a]["v"]
            if v is not None and v > 0:
                y_vals.append(v)
    if band:
        low, cent, high, _ = band
        y_vals += [low, cent, high]

    if y_vals:
        ymax = max(y_vals)
        y_top = int(math.ceil((ymax * 1.15) / 1000) * 1000)  # arredonda para 1000
        ax.set_ylim(0, y_top)
        ax.yaxis.set_major_locator(MultipleLocator(base=4000))  # ticks a cada 4 kB (ajuste se quiser)

    ax.grid(True, which="major", axis="y", linewidth=0.6, zorder=0)

    # RSA-15360 estimado (ghostbar ancorada na coluna 256-bits)
    if band:
        j = groups.index("256"); i = algos.index("RSA")
        xc = x[j] + (i - 1) * BAR_WIDTH
        left = xc - BAR_WIDTH/2
        low, cent, high, _ = band

        if ESTIMATE_PRESENTATION.lower() == "ghostbar":
            ax.add_patch(Rectangle(
                (left, low), BAR_WIDTH, max(high - low, 0),
                facecolor="none", edgecolor=COLORS["RSA"],
                hatch="//", linewidth=1.1, zorder=2, label="RSA-15360 (estimativa)"
            ))
            ax.plot([left, left+BAR_WIDTH], [low, low], lw=1.0, color=COLORS["RSA"], zorder=5)
            if SHOW_CENTRAL_MARK:
                ax.plot([left, left+BAR_WIDTH], [cent, cent], ls="--", lw=1.2, color=COLORS["RSA"], zorder=5)
            ax.text(xc, high*1.02, "estimado*", ha="center", va="bottom", fontsize=9)
            fig.text(0.01, 0.01, "*Extrapolado linearmente de RSA-3072/7680 (heap); não medido.", fontsize=9)
        else:
            text = (f"RSA-15360 (estimativa)\n"
                    f"faixa: {fmt_bytes_int(low)}–{fmt_bytes_int(high)}\n"
                    f"central: {fmt_bytes_int(cent)}")
            ax.annotate(
                text, xy=(xc, cent), xycoords="data",
                xytext=(0.965, 0.86), textcoords="axes fraction",
                ha="right", va="top", bbox=CALLOUT_BOX_KW,
                arrowprops=dict(arrowstyle="->", color="#6b4ca5", lw=1.0)
            )
            if SHOW_CENTRAL_MARK:
                ax.hlines(cent, left, left+BAR_WIDTH, linestyles="--", lw=1.2, color=COLORS["RSA"], zorder=5)
            fig.text(0.01, 0.01, "Estimativa linear baseada em RSA-3072/7680 (heap); não medido.", fontsize=9)

    # legenda
    ax.legend(title="Algoritmo", ncols=3, frameon=False,
              loc="upper center", bbox_to_anchor=(0.5, 1.02), borderaxespad=0.2)

    plt.tight_layout(pad=0.2)
    out_png = txt_path.with_suffix(".heap.png")
    out_svg = txt_path.with_suffix(".heap.svg")
    plt.savefig(out_png, dpi=220, bbox_inches="tight")
    plt.savefig(out_svg, bbox_inches="tight")
    print(f"Gráficos salvos em: {out_png} e {out_svg}")

if __name__ == "__main__":
    main()
