"""
camadas.py — Núcleo de segurança do protótipo "Segurança de Dados em Aplicações Web".

Implementa CINCO níveis de defesa ACUMULATIVOS. Cada nível herda todas as
proteções do nível anterior e acrescenta UMA nova camada. A hipótese do
trabalho é que, à medida que as camadas são reforçadas, o acesso não
autorizado se torna progressivamente mais difícil.

Níveis:
    N0  Senha em texto puro, sem qualquer proteção.
    N1  + Hash forte de senha (Argon2id) com sal por usuário.
    N2  + Rate limiting e bloqueio temporário de conta (anti força-bruta).
    N3  + MFA/TOTP (RFC 6238) como segundo fator.
    N4  + Zero Trust: reverificação por sessão curta e detecção de replay de código.
    N5  + Autenticação resistente a phishing (WebAuthn/FIDO2) com origin binding.

Referências de projeto:
    RFC 6238 (TOTP); NIST SP 800-63B Rev.4 (Argon2id, AAL, MFA);
    OWASP Password Storage Cheat Sheet (Argon2id); CISA (FIDO/WebAuthn como
    único método resistente a phishing).
"""

import time
import hmac
import hashlib
import secrets
from dataclasses import dataclass, field

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Um único hasher Argon2id compartilhado (parâmetros moderados p/ ambiente de teste).
_ph = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)


@dataclass
class Usuario:
    """Registro de um usuário no 'banco' em memória."""
    login: str
    # N0 guarda a senha crua; N1+ guarda o hash Argon2id.
    senha_plana: str = ""
    senha_hash: str = ""
    # Segredo TOTP (N3+).
    totp_secret: str = ""
    # Chave pública simulada do autenticador FIDO2 vinculada à origem legítima (N5).
    fido_pubkey: str = ""
    origem_legitima: str = "https://app.local"


@dataclass
class EstadoDefesa:
    """Estado mutável usado pelas camadas de rate limiting e replay."""
    tentativas: dict = field(default_factory=dict)   # login -> [timestamps]
    bloqueios: dict = field(default_factory=dict)     # login -> timestamp de fim do bloqueio
    codigos_usados: dict = field(default_factory=dict)  # login -> set de códigos TOTP já aceitos


# ---------------------------------------------------------------------------
# Parâmetros das camadas
# ---------------------------------------------------------------------------
JANELA_RATE = 60          # segundos observados para contar tentativas
MAX_TENTATIVAS = 5        # tentativas falhas antes do bloqueio
DURACAO_BLOQUEIO = 300    # segundos de bloqueio após exceder o limite


class Autenticador:
    """
    Verificador configurável por nível. Recebe o número do nível (0..5) e
    aplica exatamente as camadas correspondentes.
    """

    def __init__(self, nivel: int):
        if not 0 <= nivel <= 5:
            raise ValueError("nível deve estar entre 0 e 5")
        self.nivel = nivel
        self.usuarios: dict[str, Usuario] = {}
        self.estado = EstadoDefesa()

    # ---- Cadastro -------------------------------------------------------
    def cadastrar(self, login: str, senha: str) -> Usuario:
        u = Usuario(login=login)
        if self.nivel == 0:
            u.senha_plana = senha
        else:
            u.senha_hash = _ph.hash(senha)
        if self.nivel >= 3:
            u.totp_secret = pyotp.random_base32()
        if self.nivel >= 5:
            # Simula o par de chaves do autenticador FIDO2 ligado à origem.
            u.fido_pubkey = secrets.token_hex(16)
        self.usuarios[login] = u
        return u

    # ---- Camadas isoladas ----------------------------------------------
    def _senha_ok(self, u: Usuario, senha: str) -> bool:
        if self.nivel == 0:
            return secrets.compare_digest(u.senha_plana, senha)
        try:
            return _ph.verify(u.senha_hash, senha)
        except VerifyMismatchError:
            return False

    def _rate_limit_bloqueado(self, login: str, agora: float) -> bool:
        """N2+: retorna True se a conta está bloqueada agora."""
        if self.nivel < 2:
            return False
        fim = self.estado.bloqueios.get(login, 0)
        return agora < fim

    def _registrar_falha(self, login: str, agora: float) -> None:
        if self.nivel < 2:
            return
        janela = [t for t in self.estado.tentativas.get(login, []) if agora - t < JANELA_RATE]
        janela.append(agora)
        self.estado.tentativas[login] = janela
        if len(janela) >= MAX_TENTATIVAS:
            self.estado.bloqueios[login] = agora + DURACAO_BLOQUEIO
            self.estado.tentativas[login] = []

    def _totp_ok(self, u: Usuario, codigo: str, agora: float) -> bool:
        """N3+: valida o código TOTP. N4+ também rejeita replay de código já usado."""
        if self.nivel < 3:
            return True  # camada inexistente neste nível
        totp = pyotp.TOTP(u.totp_secret)
        valido = totp.verify(codigo, for_time=int(agora), valid_window=1)
        if not valido:
            return False
        if self.nivel >= 4:
            usados = self.estado.codigos_usados.setdefault(u.login, set())
            if codigo in usados:
                return False  # replay detectado (Zero Trust: nunca confie, sempre verifique)
            usados.add(codigo)
        return True

    def _origem_ok(self, u: Usuario, origem_apresentada: str) -> bool:
        """
        N5: origin binding do WebAuthn/FIDO2. A resposta do autenticador só é
        válida se a origem que a solicitou for a origem legítima. Num ataque
        de phishing em tempo real (AiTM), a origem é a do site falso, então
        a verificação falha mesmo que a vítima complete o login.
        """
        if self.nivel < 5:
            return True
        return secrets.compare_digest(u.origem_legitima, origem_apresentada)

    # ---- Fluxo completo de autenticação --------------------------------
    def autenticar(self, login: str, senha: str, codigo_totp: str = "",
                   origem: str = "https://app.local", agora: float | None = None) -> bool:
        agora = time.time() if agora is None else agora
        u = self.usuarios.get(login)
        if u is None:
            return False
        if self._rate_limit_bloqueado(login, agora):
            return False
        if not self._senha_ok(u, senha):
            self._registrar_falha(login, agora)
            return False
        if not self._totp_ok(u, codigo_totp, agora):
            self._registrar_falha(login, agora)
            return False
        if not self._origem_ok(u, origem):
            self._registrar_falha(login, agora)
            return False
        return True


NOMES_NIVEIS = {
    0: "N0 – Senha em texto puro",
    1: "N1 – + Hash Argon2id",
    2: "N2 – + Rate limiting / bloqueio",
    3: "N3 – + MFA/TOTP",
    4: "N4 – + Zero Trust (anti-replay)",
    5: "N5 – + FIDO2/WebAuthn (anti-phishing)",
}
