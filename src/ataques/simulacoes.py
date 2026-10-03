"""
simulacoes.py — Executa quatro famílias de ataque contra cada um dos seis
níveis de defesa e mede a taxa de acessos indevidos BLOQUEADOS.

Ataques:
    A. Reuso de credencial vazada  — o atacante já tem login e senha corretos
       (cenário MOAB / Min. da Saúde). Mede se a senha sozinha basta.
    B. Força-bruta de senha        — o atacante tenta muitas senhas por segundo.
    C. Roubo/replay de código TOTP — o atacante captura um código e tenta reusá-lo.
    D. Phishing em tempo real (AiTM)— a vítima faz login completo num site falso;
       o atacante retransmite senha + TOTP válidos, mas a partir da origem falsa.

Métrica principal (variável dependente): taxa de bloqueio =
    tentativas de acesso indevido barradas / total de tentativas de acesso indevido.
Quanto mais alta, mais resiliente a camada.
"""

import time
import json
import statistics
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "camadas"))
import pyotp
from camadas import Autenticador, NOMES_NIVEIS

SENHA_REAL = "S3nh@-Forte-Do-Usuario!"
LOGIN = "vitima@empresa.gov.br"
N_TENTATIVAS = 80  # por ataque, por nível


def novo_ambiente(nivel):
    aut = Autenticador(nivel)
    aut.cadastrar(LOGIN, SENHA_REAL)
    return aut


def ataque_credencial_vazada(nivel):
    """O atacante tem a senha correta. Sem 2º fator, entra."""
    bloqueados = 0
    for _ in range(N_TENTATIVAS):
        aut = novo_ambiente(nivel)  # ambiente limpo: isola do rate limiting
        u = aut.usuarios[LOGIN]
        # O atacante NÃO tem o segredo TOTP nem o autenticador FIDO.
        entrou = aut.autenticar(LOGIN, SENHA_REAL,
                                codigo_totp="000000",
                                origem="https://site-falso.com")
        if not entrou:
            bloqueados += 1
    return bloqueados / N_TENTATIVAS


def ataque_forca_bruta(nivel):
    """
    Força-bruta online contra a camada de SENHA. Retorna a taxa de bloqueio:
    a fração das tentativas indevidas que o sistema barrou.

    Sem rate limiting (N0-N1), todas as tentativas erradas são processadas —
    o atacante pode seguir indefinidamente até acertar. Com rate limiting
    (N2+), após MAX_TENTATIVAS a conta é bloqueada e as tentativas seguintes
    são recusadas de imediato, cortando drasticamente o espaço de busca.
    """
    aut = novo_ambiente(nivel)
    u = aut.usuarios[LOGIN]
    base = time.time()
    processadas = 0  # tentativas que chegaram a verificar a senha
    for i in range(N_TENTATIVAS):
        agora = base + i / 3.0  # ~3 tentativas por segundo
        antes = aut._rate_limit_bloqueado(LOGIN, agora)
        aut.autenticar(LOGIN, f"tentativa_{i}", codigo_totp="000000",
                       origem="https://site-falso.com", agora=agora)
        if not antes:
            processadas += 1
    # A "resiliência" é a fração de tentativas que NÃO chegaram a testar a senha.
    barradas = N_TENTATIVAS - processadas
    return barradas / N_TENTATIVAS


def contar_tentativas_ate_bloqueio(nivel, teto=500):
    """
    Métrica auxiliar: quantas tentativas o atacante consegue antes do bloqueio.
    Usa diretamente as rotinas de rate limiting (sem passar pelo Argon2) porque
    só nos interessa quando o limitador dispara.
    """
    if nivel < 2:
        return teto  # sem rate limiting: efetivamente ilimitado
    aut = novo_ambiente(nivel)
    base = time.time()
    for i in range(teto):
        agora = base + i / 3.0
        if aut._rate_limit_bloqueado(LOGIN, agora):
            return i
        aut._registrar_falha(LOGIN, agora)
    return teto


def ataque_replay_totp(nivel):
    """
    O atacante tem senha correta e captura UM código TOTP válido (via malware/
    phishing) e tenta reusá-lo várias vezes dentro da janela.
    """
    bloqueados = 0
    for _ in range(N_TENTATIVAS):
        aut = novo_ambiente(nivel)
        u = aut.usuarios[LOGIN]
        agora = time.time()
        if nivel >= 3:
            codigo = pyotp.TOTP(u.totp_secret).at(int(agora))
        else:
            codigo = "000000"
        # 1ª utilização (legítima ou não) e depois REUSO pelo atacante:
        aut.autenticar(LOGIN, SENHA_REAL, codigo_totp=codigo,
                       origem=u.origem_legitima, agora=agora)
        entrou_reuso = aut.autenticar(LOGIN, SENHA_REAL, codigo_totp=codigo,
                                      origem="https://site-falso.com", agora=agora + 1)
        if not entrou_reuso:
            bloqueados += 1
    return bloqueados / N_TENTATIVAS


def ataque_phishing_aitm(nivel):
    """
    Phishing em tempo real: a vítima entrega senha e código TOTP num site falso.
    O atacante retransmite tudo, mas a origem da requisição é a do site falso.
    Só o origin binding do FIDO2 (N5) barra isso.
    """
    bloqueados = 0
    for _ in range(N_TENTATIVAS):
        aut = novo_ambiente(nivel)
        u = aut.usuarios[LOGIN]
        agora = time.time()
        codigo = pyotp.TOTP(u.totp_secret).at(int(agora)) if nivel >= 3 else "000000"
        # O atacante repassa credenciais válidas a partir da origem FALSA:
        entrou = aut.autenticar(LOGIN, SENHA_REAL, codigo_totp=codigo,
                                origem="https://site-falso.com", agora=agora)
        if not entrou:
            bloqueados += 1
    return bloqueados / N_TENTATIVAS


ATAQUES = {
    "Reuso de credencial vazada": ataque_credencial_vazada,
    "Forca-bruta de senha": ataque_forca_bruta,
    "Replay de codigo TOTP": ataque_replay_totp,
    "Phishing em tempo real (AiTM)": ataque_phishing_aitm,
}


def medir_latencia(nivel, repeticoes=30):
    """Tempo médio (ms) de uma autenticação legítima bem-sucedida."""
    aut = novo_ambiente(nivel)
    u = aut.usuarios[LOGIN]
    tempos = []
    for _ in range(repeticoes):
        agora = time.time()
        codigo = pyotp.TOTP(u.totp_secret).at(int(agora)) if nivel >= 3 else ""
        # zera anti-replay para permitir logins repetidos na medição
        aut.estado.codigos_usados.clear()
        t0 = time.perf_counter()
        aut.autenticar(LOGIN, SENHA_REAL, codigo_totp=codigo,
                       origem=u.origem_legitima, agora=agora)
        tempos.append((time.perf_counter() - t0) * 1000)
    return statistics.mean(tempos), statistics.pstdev(tempos)


def executar():
    resultados = {"taxa_bloqueio": {}, "latencia_ms": {}, "tentativas_ate_bloqueio": {}}
    for nivel in range(6):
        nome = NOMES_NIVEIS[nivel]
        resultados["taxa_bloqueio"][nome] = {}
        for nome_ataque, fn in ATAQUES.items():
            taxa = fn(nivel)
            resultados["taxa_bloqueio"][nome][nome_ataque] = round(taxa * 100, 1)
        media, dp = medir_latencia(nivel)
        resultados["latencia_ms"][nome] = {"media": round(media, 2), "desvio": round(dp, 2)}
        n = contar_tentativas_ate_bloqueio(nivel)
        resultados["tentativas_ate_bloqueio"][nome] = ("ilimitado" if n >= 10000 else n)
        print(f"[ok] {nome}")
    return resultados


if __name__ == "__main__":
    res = executar()
    saida = os.path.join(os.path.dirname(__file__), "..", "..", "resultados", "resultados.json")
    with open(saida, "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print("\nResultados salvos em resultados/resultados.json")
    print(json.dumps(res, ensure_ascii=False, indent=2))
