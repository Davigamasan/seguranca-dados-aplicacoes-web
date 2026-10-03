"""Gera as figuras dos resultados a partir de resultados/resultados.json."""
import json
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

BASE = os.path.join(os.path.dirname(__file__), "..", "..", "resultados")
d = json.load(open(os.path.join(BASE, "resultados.json"), encoding="utf-8"))

rotulos_niveis = ["N0", "N1", "N2", "N3", "N4", "N5"]
tb = d["taxa_bloqueio"]
niveis = list(tb.keys())
ataques = list(tb[niveis[0]].keys())
rot_ataques = ["Reuso de credencial\nvazada", "Força-bruta\nde senha",
               "Replay de\ncódigo TOTP", "Phishing em\ntempo real (AiTM)"]

# ---- Figura 1: heatmap taxa de bloqueio por camada x ataque ----
matriz = np.array([[tb[n][a] for a in ataques] for n in niveis])
fig, ax = plt.subplots(figsize=(8, 5))
im = ax.imshow(matriz, cmap="RdYlGn", vmin=0, vmax=100, aspect="auto")
ax.set_xticks(range(len(ataques)))
ax.set_xticklabels(rot_ataques, fontsize=9)
ax.set_yticks(range(len(niveis)))
ax.set_yticklabels(rotulos_niveis)
for i in range(len(niveis)):
    for j in range(len(ataques)):
        ax.text(j, i, f"{matriz[i, j]:.0f}%", ha="center", va="center",
                color="black", fontsize=10, fontweight="bold")
ax.set_title("Taxa de bloqueio de acessos indevidos por camada de defesa",
             fontsize=11, pad=12)
ax.set_ylabel("Camadas de defesa acumuladas")
cbar = fig.colorbar(im, ax=ax, shrink=0.8)
cbar.set_label("% de tentativas bloqueadas")
plt.tight_layout()
plt.savefig(os.path.join(os.path.dirname(__file__), "..", "..", "docs", "figuras", "fig1_heatmap.png"), dpi=150)
plt.close()

# ---- Figura 2: resiliência global acumulada ----
media_por_nivel = [np.mean([tb[n][a] for a in ataques]) for n in niveis]
fig, ax = plt.subplots(figsize=(8, 4.5))
cores = plt.cm.viridis(np.linspace(0.15, 0.85, len(niveis)))
barras = ax.bar(rotulos_niveis, media_por_nivel, color=cores)
ax.set_ylim(0, 105)
ax.set_ylabel("Resiliência média (% de ataques bloqueados)")
ax.set_xlabel("Camadas de defesa acumuladas")
ax.set_title("Resiliência global cresce à medida que as camadas são reforçadas",
             fontsize=11)
for b, v in zip(barras, media_por_nivel):
    ax.text(b.get_x() + b.get_width() / 2, v + 2, f"{v:.0f}%",
            ha="center", fontsize=9, fontweight="bold")
plt.tight_layout()
plt.savefig(os.path.join(os.path.dirname(__file__), "..", "..", "docs", "figuras", "fig2_resiliencia.png"), dpi=150)
plt.close()

# ---- Figura 3: custo (latência) vs segurança ----
lat = d["latencia_ms"]
medias = [lat[n]["media"] for n in niveis]
fig, ax = plt.subplots(figsize=(8, 4.5))
ax.plot(rotulos_niveis, medias, marker="o", color="#c0392b", linewidth=2)
ax.set_ylabel("Latência média de autenticação (ms)")
ax.set_xlabel("Camadas de defesa acumuladas")
ax.set_title("Custo de desempenho por camada (login legítimo)", fontsize=11)
for x, y in zip(rotulos_niveis, medias):
    ax.annotate(f"{y:.1f} ms", (x, y), textcoords="offset points",
                xytext=(0, 8), ha="center", fontsize=8)
ax.set_ylim(0, max(medias) * 1.3)
plt.tight_layout()
plt.savefig(os.path.join(os.path.dirname(__file__), "..", "..", "docs", "figuras", "fig3_latencia.png"), dpi=150)
plt.close()

print("Figuras geradas:", os.listdir(BASE))
