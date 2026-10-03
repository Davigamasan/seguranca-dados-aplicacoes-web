"""
app.py — Aplicação Flask demonstrável do protótipo em camadas.

Permite ao grupo mostrar ao vivo, na banca:
  - cadastro de usuário com hash Argon2id;
  - configuração de MFA/TOTP via QR Code (Google Authenticator);
  - login protegido pelas camadas do nível escolhido;
  - o bloqueio por rate limiting em ação.

Uso:
    python app/app.py
    Acesse http://127.0.0.1:5000
"""

import io
import base64
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "camadas"))
from flask import Flask, request, session, redirect, url_for, render_template_string
import pyotp
import qrcode
from camadas import Autenticador, NOMES_NIVEIS

app = Flask(__name__)
app.secret_key = "chave-de-demonstracao-tcc"

# Nível ativo da demonstração (pode ser trocado na interface).
NIVEL = int(os.environ.get("NIVEL_DEMO", "5"))
aut = Autenticador(NIVEL)

PAGINA = """
<!doctype html><html lang=pt-br><head><meta charset=utf-8>
<title>Protótipo — Segurança em Camadas</title>
<style>
 body{font-family:system-ui,Arial;max-width:640px;margin:40px auto;padding:0 16px;color:#1a2332}
 h1{font-size:20px} .card{border:1px solid #d0d7de;border-radius:10px;padding:18px;margin:14px 0}
 input,select{padding:8px;width:100%;box-sizing:border-box;margin:4px 0 12px}
 button{background:#0b4f8a;color:#fff;border:0;padding:10px 16px;border-radius:8px;cursor:pointer}
 .ok{color:#1a7f37;font-weight:700}.erro{color:#cf222e;font-weight:700}
 .nivel{background:#eef3f8;padding:6px 10px;border-radius:6px;font-size:13px}
 img{margin-top:10px;border:1px solid #ccc}
</style></head><body>
<h1>Protótipo — Defesa em Profundidade + Zero Trust</h1>
<p class=nivel>Nível ativo: <b>{{nivel_nome}}</b></p>
{% if msg %}<p class="{{cls}}">{{msg}}</p>{% endif %}

<div class=card>
 <h3>1. Cadastrar usuário</h3>
 <form method=post action="/cadastrar">
  <input name=login placeholder="login (e-mail)" required>
  <input name=senha type=password placeholder="senha" required>
  <button>Cadastrar</button>
 </form>
</div>

{% if qr %}
<div class=card>
 <h3>2. Configurar MFA/TOTP</h3>
 <p>Escaneie no Google Authenticator:</p>
 <img src="data:image/png;base64,{{qr}}" width=180>
 <p>Segredo: <code>{{segredo}}</code></p>
</div>
{% endif %}

<div class=card>
 <h3>3. Fazer login</h3>
 <form method=post action="/login">
  <input name=login placeholder="login" required>
  <input name=senha type=password placeholder="senha" required>
  <input name=totp placeholder="código TOTP (se aplicável)">
  <select name=origem>
   <option value="https://app.local">Origem legítima (app.local)</option>
   <option value="https://site-falso.com">Site falso (simular phishing)</option>
  </select>
  <button>Entrar</button>
 </form>
</div>
</body></html>
"""


@app.route("/")
def index():
    return render_template_string(PAGINA, nivel_nome=NOMES_NIVEIS[NIVEL],
                                  msg=session.pop("msg", None),
                                  cls=session.pop("cls", ""),
                                  qr=session.pop("qr", None),
                                  segredo=session.pop("segredo", None))


@app.route("/cadastrar", methods=["POST"])
def cadastrar():
    login = request.form["login"]
    senha = request.form["senha"]
    u = aut.cadastrar(login, senha)
    session["msg"] = f"Usuário {login} cadastrado com {NOMES_NIVEIS[NIVEL]}."
    session["cls"] = "ok"
    if NIVEL >= 3:
        uri = pyotp.TOTP(u.totp_secret).provisioning_uri(name=login, issuer_name="TCC-BrazCubas")
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        session["qr"] = base64.b64encode(buf.getvalue()).decode()
        session["segredo"] = u.totp_secret
    return redirect(url_for("index"))


@app.route("/login", methods=["POST"])
def login():
    ok = aut.autenticar(request.form["login"], request.form["senha"],
                        codigo_totp=request.form.get("totp", ""),
                        origem=request.form.get("origem", "https://app.local"))
    if ok:
        session["msg"] = "Acesso concedido — todas as camadas foram satisfeitas."
        session["cls"] = "ok"
    else:
        session["msg"] = "Acesso negado — alguma camada de defesa barrou a tentativa."
        session["cls"] = "erro"
    return redirect(url_for("index"))


if __name__ == "__main__":
    print(f"Protótipo no nível {NIVEL} ({NOMES_NIVEIS[NIVEL]})")
    app.run(debug=False, port=5000)
