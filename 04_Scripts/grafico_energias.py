# grafico_energia_por_iteracao.py
# Barras agrupadas (128/192/256 × ML-KEM/ECDH/RSA), Y log, cores fixas.
# TXT: "Rótulo: valor_em_mJ" (aceita vírgula decimal; "NA" pula).
# Mantém estimativa do RSA-15360 como ghostbar (faixa entre 2^B_LOW e 2^B_HIGH vezes o 7680),
# agora aplicada sobre energia por iteração (mJ).

import sys, math
from pathlib import Path
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle
from matplotlib.ticker import LogLocator, LogFormatterMathtext, NullLocator

# ----- Config -----
B_LOW  = 2.0     # expoente mínimo relativo ao RSA-7680 (2^B_LOW)
B_HIGH = 3.5     # expoente máximo relativo ao RSA-7680 (2^B_HIGH)
SHOW_CENTRAL_MARK = True
ESTIMATE_PRESENTATION = "ghostbar"   # "callout" (padrão) ou "ghostbar"

COLORS = {"ML-KEM": "#1f77b4", "ECDH": "#ff7f0e", "RSA": "#9467bd"}
BAR_WIDTH = 0.25

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
    v_mJ = _num(first)
    if v_mJ is not None and v_mJ <= 0:
        v_mJ = None
    return (lbl, v_mJ)

def compute_rsa15360_band(e3072, e7680):
    """Extrapola faixa e ponto central (mJ) para 15360 a partir de 3072/7680."""
    if e3072 is None or e7680 is None or e3072 <= 0 or e7680 <= 0:
        return None
    # Ajuste de expoente efetivo b entre 3072->7680
    b_fit = math.log(e7680 / e3072) / math.log(7680 / 3072)
    low  = e7680 * (2 ** B_LOW)
    cent = e7680 * (2 ** b_fit)
    high = e7680 * (2 ** B_HIGH)
    return (low, cent, high, b_fit)

def fmt_mJ(x: float) -> str:
    # 3 algarismos significativos em mJ
    return f"{x:.3g} mJ"

def main():
    if len(sys.argv) < 2:
        print("Uso: python grafico_energia_por_iteracao.py <arquivo_txt>")
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
            k, v_mJ = parsed
            if k in mapping:
                a, sec = mapping[k]
                data[sec][a] = {"v": v_mJ}

    # Estimativa RSA-15360 (mJ)
    rsa3072 = data["128"]["RSA"]["v"]
    rsa7680 = data["192"]["RSA"]["v"]
    band = compute_rsa15360_band(rsa3072, rsa7680)
    if band:
        low, cent, high, b_fit = band
        print(f"[Predição RSA-15360] b_ajustado={b_fit:.4f}; low={low:.6g} mJ; central={cent:.6g} mJ; high={high:.6g} mJ")
    else:
        print("[Predição RSA-15360] Não foi possível estimar (faltam 3072/7680).")

    # ----- Plot -----
    x = np.arange(len(groups))
    fig, ax = plt.subplots(figsize=(9.6, 5.4))

    # barras
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

    # eixos
    ax.set_xticks(x, [f"{g}-bits" for g in groups])
    ax.set_xlabel("Nível de segurança")
    ax.set_yscale("log")
    ax.yaxis.set_major_locator(LogLocator(base=10.0))
    ax.yaxis.set_major_formatter(LogFormatterMathtext(base=10.0))
    ax.yaxis.set_minor_locator(NullLocator())
    ax.grid(True, which="major", axis="y", linewidth=0.6, zorder=0)
    ax.set_ylabel("Energia por iteração (mJ) — escala log10")

    # limites Y (considerando também a faixa estimada do RSA-15360)
    y_vals = []
    for g in groups:
        for a in algos:
            v = data[g][a]["v"]
            if v is not None and v > 0:
                y_vals.append(v)
    if band:
        y_vals += [low, cent, high]

    if y_vals:
        ymin = min(yy for yy in y_vals if yy > 0)
        ymax = max(y_vals)
        y_bottom = 10 ** math.floor(math.log10(ymin))
        y_top    = 10 ** math.ceil(math.log10(ymax * 1.25))
        if y_top <= y_bottom:
            y_top = y_bottom * 10
        ax.set_ylim(y_bottom, y_top)

    # RSA-15360 estimado (ghostbar ancorada na coluna 256-bits)
    if band:
        j = groups.index("256"); i = algos.index("RSA")
        xc = x[j] + (i - 1) * BAR_WIDTH
        left = xc - BAR_WIDTH/2

        if ESTIMATE_PRESENTATION.lower() == "ghostbar":
            ax.add_patch(Rectangle(
                (left, low), BAR_WIDTH, max(high - low, 0),
                facecolor="none", edgecolor=COLORS["RSA"],
                hatch="//", linewidth=1.1, zorder=2, label="RSA-15360 (estimativa)"
            ))
            ax.plot([left, left+BAR_WIDTH], [low, low], lw=1.0, color=COLORS["RSA"], zorder=5)
            if SHOW_CENTRAL_MARK:
                ax.plot([left, left+BAR_WIDTH], [cent, cent], ls="--", lw=1.2, color=COLORS["RSA"], zorder=5)
            # nota curta acima da faixa
            ax.text(xc, high*1.05, "estimado*", ha="center", va="bottom", fontsize=9)
            fig.text(0.01, 0.01, "*Extrapolado de RSA-3072/7680 (energia/op); não medido.", fontsize=9)
        else:
            text = (f"RSA-15360 (estimativa)\n"
                    f"faixa: {fmt_mJ(low)}–{fmt_mJ(high)}\n"
                    f"central: {fmt_mJ(cent)}")
            ax.annotate(
                text, xy=(xc, cent), xycoords="data",
                xytext=(0.965, 0.86), textcoords="axes fraction",
                ha="right", va="top", bbox=CALLOUT_BOX_KW,
                arrowprops=dict(arrowstyle="->", color="#6b4ca5", lw=1.0)
            )
            if SHOW_CENTRAL_MARK:
                ax.hlines(cent, left, left+BAR_WIDTH, linestyles="--", lw=1.2, color=COLORS["RSA"], zorder=5)
            fig.text(0.01, 0.01, "Estimativa baseada em RSA-3072/7680 (energia/op); não medido.", fontsize=9)

    # legenda
    ax.legend(title="Algoritmo", ncols=3, frameon=False,
              loc="upper center", bbox_to_anchor=(0.5, 1.02), borderaxespad=0.2)

    plt.tight_layout(pad=0.2)
    out_png = txt_path.with_suffix(".png")
    out_svg = txt_path.with_suffix(".svg")
    plt.savefig(out_png, dpi=220, bbox_inches="tight")
    plt.savefig(out_svg, bbox_inches="tight")
    print(f"Gráficos salvos em: {out_png} e {out_svg}")

if __name__ == "__main__":
    main()
