# grafico_tempos_com_faixa_iqr_top.py

import sys, math
from pathlib import Path
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle
from matplotlib.ticker import LogLocator, LogFormatterMathtext, NullLocator

# ----- Config -----
B_LOW  = 2.0
B_HIGH = 3.5
SHOW_CENTRAL_MARK = True
ESTIMATE_PRESENTATION = "ghostbar"   # "callout" (padrão) ou "ghostbar"
COLORS = {"ML-KEM": "#1f77b4", "ECDH": "#ff7f0e", "RSA": "#9467bd"}
BAR_WIDTH = 0.25
ELINEWIDTH = 1.2
CAPSIZE = 0.0
HIDE_TINY_WHISKERS_REL = 1
CALLOUT_BOX_KW = dict(boxstyle="round,pad=0.3", facecolor="#ede1ff",
                      alpha=0.6, edgecolor="#6b4ca5", linewidth=1.0)

def _num(s: str):
    s = s.strip()
    if s.upper() in {"NA", "N/A", ""}: return None
    s = s.replace(",", ".")
    try: return float(s)
    except: return None

def normalize_label(lbl: str) -> str:
    x = lbl.strip().lower()
    x = x.replace(" ", "").replace("_", "").replace("—", "-").replace("–", "-")
    x = x.replace("crystal-kybers", "ml-kem").replace("crystalkybers", "ml-kem").replace("kyber", "ml-kem")
    return x

def parse_line(line: str):
    if ":" not in line: return None
    k, rest = line.split(":", 1)
    lbl = normalize_label(k)
    parts = [p.strip() for p in rest.split("/")]
    v = _num(parts[0]) if parts else None
    q1_us = q3_us = iqr_us = None
    if len(parts) >= 3:
        q1_us = _num(parts[1]); q3_us = _num(parts[2])
    elif len(parts) == 2:
        iqr_us = _num(parts[1])
    if v is not None and v <= 0: v = None
    if q1_us is not None and q3_us is not None and q3_us < q1_us:
        q1_us, q3_us = q3_us, q1_us
    return lbl, v, q1_us, q3_us, iqr_us

def compute_rsa15360_band(t3072, t7680):
    if t3072 is None or t7680 is None or t3072 <= 0 or t7680 <= 0: return None
    b_fit = math.log(t7680/t3072) / math.log(7680/3072)
    low  = t7680 * (2 ** B_LOW)
    cent = t7680 * (2 ** b_fit)
    high = t7680 * (2 ** B_HIGH)
    return (low, cent, high, b_fit)

def fmt_s(x: float) -> str:
    # 3 algarismos significativos em segundos
    return f"{x:.3g}s"

def main():
    if len(sys.argv) < 2:
        print("Uso: python grafico_tempos_com_faixa_iqr_top.py <arquivo_txt>")
        sys.exit(1)

    txt_path = Path(sys.argv[1])
    lines = txt_path.read_text(encoding="utf-8").splitlines()

    mapping = {
        "ml-kem-512": ("ML-KEM","128"), "mlkem-512": ("ML-KEM","128"), "kyber-512": ("ML-KEM","128"),
        "ml-kem-768": ("ML-KEM","192"), "mlkem-768": ("ML-KEM","192"), "kyber-768": ("ML-KEM","192"),
        "ml-kem-1024":("ML-KEM","256"), "mlkem-1024":("ML-KEM","256"), "kyber-1024":("ML-KEM","256"),
        "p-256": ("ECDH","128"), "p256": ("ECDH","128"), "ecdh-p256": ("ECDH","128"),
        "p-384": ("ECDH","192"), "p384": ("ECDH","192"), "ecdh-p384": ("ECDH","192"),
        "p-521": ("ECDH","256"), "p521": ("ECDH","256"), "ecdh-p521": ("ECDH","256"),
        "rsa-3072": ("RSA","128"), "rsa3072": ("RSA","128"),
        "rsa-7680": ("RSA","192"), "rsa7680": ("RSA","192"),
        "rsa-15360":("RSA","256"), "rsa15360":("RSA","256"),
    }

    groups, algos = ["128","192","256"], ["ML-KEM","ECDH","RSA"]
    data = {g: {a: {"v": None, "q1": None, "q3": None, "iqr": None} for a in algos} for g in groups}

    for ln in lines:
        parsed = parse_line(ln)
        if parsed:
            k, v, q1_us, q3_us, iqr_us = parsed
            if k in mapping:
                a, sec = mapping[k]
                data[sec][a] = {"v": v, "q1": q1_us, "q3": q3_us, "iqr": iqr_us}

    rsa3072 = data["128"]["RSA"]["v"]
    rsa7680 = data["192"]["RSA"]["v"]
    band = compute_rsa15360_band(rsa3072, rsa7680)
    if band:
        low, cent, high, b_fit = band
        print(f"[Predição RSA-15360] b_ajustado={b_fit:.4f}; low={low:.6g}s; central={cent:.6g}s; high={high:.6g}s")
    else:
        print("[Predição RSA-15360] Não foi possível estimar (faltam 3072/7680).")

    x = np.arange(len(groups))
    fig, ax = plt.subplots(figsize=(9.6, 5.4))

    centers = []
    for i, algo in enumerate(algos):
        offset = (i - 1) * BAR_WIDTH
        color = COLORS[algo]
        for j, g in enumerate(groups):
            obj = data[g][algo]
            v = obj["v"]
            if v is None: continue
            xc = x[j] + offset
            ax.bar(xc, v, BAR_WIDTH, color=color, edgecolor="#444", linewidth=0.5,
                   label=algo if j == 0 else None, zorder=3)
            centers.append((xc, v, obj["q1"], obj["q3"], obj["iqr"]))

    ax.set_xticks(x, [f"{g}-bits" for g in groups])
    ax.set_xlabel("Nível de segurança")
    ax.set_yscale("log")
    ax.yaxis.set_major_locator(LogLocator(base=10.0))
    ax.yaxis.set_major_formatter(LogFormatterMathtext(base=10.0))
    ax.yaxis.set_minor_locator(NullLocator())
    ax.grid(True, which="major", axis="y", linewidth=0.6, zorder=0)
    ax.set_ylabel("Tempo (s) — mediana (escala log10)")

    # ----- definir limites Y (considerando banda estimada) -----
    y_vals = []
    for _, v, q1_us, q3_us, iqr_us in centers:
        if v is None or v <= 0: continue
        y_vals.append(v)
        if q1_us is not None and q3_us is not None:
            y_vals += [q1_us/1e6, q3_us/1e6]
        elif iqr_us is not None:
            # só topo quando tiver apenas IQR
            y_vals += [v + (iqr_us/1e6)]
    if band:
        y_vals += [low, cent, high]

    if y_vals:
        ymin = min(yy for yy in y_vals if yy > 0)
        ymax = max(y_vals)
        y_bottom = 10 ** math.floor(math.log10(ymin))
        y_top    = 10 ** math.ceil(math.log10(ymax * 1.25))
        if y_top <= y_bottom: y_top = y_bottom * 10
        ax.set_ylim(y_bottom, y_top)

    # ----- whiskers (Q1/Q3 ou só IQR no topo) -----
    for xc, v, q1_us, q3_us, iqr_us in centers:
        if v is None or v <= 0: continue
        if q1_us is not None and q3_us is not None:
            q1_s, q3_s = q1_us/1e6, q3_us/1e6
            lower = max(0.0, v - q1_s)
            upper = max(0.0, q3_s - v)
        elif iqr_us is not None and iqr_us > 0:
            lower = 0.0
            upper = iqr_us/1e6
        else:
            continue
        if max(lower, upper)/v < HIDE_TINY_WHISKERS_REL:
            continue
        ax.errorbar([xc], [v], yerr=[[lower], [upper]],
                    fmt="none", elinewidth=ELINEWIDTH, capsize=CAPSIZE,
                    ecolor="black", zorder=6, clip_on=False)

    # ----- RSA-15360 estimado -----
    if band:
        j = groups.index("256"); i = algos.index("RSA")
        xc = x[j] + (i - 1) * BAR_WIDTH
        left = xc - BAR_WIDTH/2

        if ESTIMATE_PRESENTATION.lower() == "ghostbar":
            # barra hachurada (ghost) ancorada na coluna 256-bits
            ax.add_patch(Rectangle((left, low), BAR_WIDTH, max(high - low, 0),
                                   facecolor="none", edgecolor=COLORS["RSA"],
                                   hatch="//", linewidth=1.1, zorder=2,
                                   label="RSA-15360 (estimativa)"))
            ax.plot([left, left+BAR_WIDTH], [low, low], lw=1.0, color=COLORS["RSA"], zorder=5)
            if SHOW_CENTRAL_MARK:
                ax.plot([left, left+BAR_WIDTH], [cent, cent], ls="--", lw=1.2,
                        color=COLORS["RSA"], zorder=5)
            # nota curta acima da faixa
            ax.text(xc, high*1.05, "estimado*", ha="center", va="bottom", fontsize=9)
            fig.text(0.01, 0.01, "*Extrapolado de RSA-3072/7680; não medido.", fontsize=9)
        else:
            # callout fora do plot, com seta para (xc, cent)
            text = (f"RSA-15360 (estimativa)\n"
                    f"faixa: {fmt_s(low)}–{fmt_s(high)}\n"
                    f"mediana: {fmt_s(cent)}")
            ax.annotate(text,
                        xy=(xc, cent), xycoords="data",
                        xytext=(0.965, 0.86), textcoords="axes fraction",
                        ha="right", va="top",
                        bbox=CALLOUT_BOX_KW,
                        arrowprops=dict(arrowstyle="->", color="#6b4ca5", lw=1.0))
            if SHOW_CENTRAL_MARK:
                ax.hlines(cent, left, left+BAR_WIDTH, linestyles="--", lw=1.2,
                          color=COLORS["RSA"], zorder=5)
            fig.text(0.01, 0.01, "Estimativa baseada em RSA-3072/7680; não medido.", fontsize=9)

    # ----- legenda fora do eixo, topo -----
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
