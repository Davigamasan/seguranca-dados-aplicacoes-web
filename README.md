# Segurança de Dados em Aplicações Web: Protótipo de Defesa em Profundidade com Zero Trust e MFA

Protótipo funcional desenvolvido como prova de conceito para o Trabalho de Conclusão de Curso
"Segurança de Dados em Aplicações Web", do curso de Bacharelado em Sistemas de Informação do
Centro Universitário Braz Cubas.

O trabalho investiga a seguinte hipótese: à medida que camadas de defesa são adicionadas e
reforçadas em uma aplicação web, o acesso não autorizado torna-se progressivamente mais difícil.
Para avaliá-la de forma empírica, o protótipo implementa seis níveis acumulativos de segurança e
submete cada um deles a um conjunto padronizado de simulações de ataque, medindo a resiliência
resultante.

## Fundamentação

A arquitetura do protótipo apoia-se em três pilares teóricos, descritos em detalhe no artigo:

1. **Arquitetura Zero Trust (ZTA)**, conforme a norma NIST SP 800-207 (Rose et al., 2020), que
   substitui a confiança baseada em perímetro pela verificação contínua de cada recurso.
2. **Defesa em Profundidade**, que organiza controles de segurança em camadas independentes e
   sobrepostas.
3. **Autenticação de Múltiplos Fatores**, do TOTP (RFC 6238) à autenticação resistente a phishing
   baseada em FIDO2/WebAuthn, recomendada pelo NIST SP 800-63B e pela CISA.

## Níveis de defesa

Cada nível herda as proteções do anterior e acrescenta uma única camada, o que permite isolar a
contribuição de cada mecanismo.

| Nível | Camada acrescentada |
|-------|---------------------|
| N0 | Senha em texto puro, sem qualquer proteção (linha de base) |
| N1 | Hash de senha com Argon2id e sal individual por usuário |
| N2 | Limitação de taxa (rate limiting) e bloqueio temporário de conta |
| N3 | MFA/TOTP (RFC 6238) como segundo fator de autenticação |
| N4 | Controles Zero Trust: verificação de sessão e rejeição de reuso de código (anti-replay) |
| N5 | Autenticação resistente a phishing (FIDO2/WebAuthn) com vinculação de origem |

## Famílias de ataque simuladas

- **Reuso de credencial vazada**: o atacante já possui a senha correta, reproduzindo o cenário
  dos vazamentos MOAB (2024) e do Ministério da Saúde (2020).
- **Força-bruta de senha**: tentativas sucessivas contra a camada de senha.
- **Replay de código TOTP**: captura e reapresentação de um código válido.
- **Phishing em tempo real (adversary-in-the-middle)**: a vítima fornece senha e código válidos
  a partir de uma origem fraudulenta.

## Estrutura do repositório

```
.
├── src/
│   ├── camadas/
│   │   └── camadas.py        Núcleo de segurança: os seis níveis acumulativos
│   ├── ataques/
│   │   ├── simulacoes.py     Executa as simulações e gera resultados/resultados.json
│   │   └── graficos.py       Gera as figuras a partir dos resultados
│   └── app.py                Aplicação Flask demonstrável (login, QR Code TOTP)
├── resultados/
│   └── resultados.json       Saída das simulações (taxa de bloqueio e latência)
├── docs/
│   └── figuras/              Figuras geradas para o artigo
├── requirements.txt
├── CITATION.cff
├── LICENSE
└── README.md
```

## Requisitos

- Python 3.10 ou superior
- Dependências listadas em `requirements.txt`

## Instalação

```
git clone https://github.com/<usuario>/seguranca-dados-aplicacoes-web.git
cd seguranca-dados-aplicacoes-web
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Execução

Executar as simulações de ataque e gerar os resultados:

```
python src/ataques/simulacoes.py
```

Gerar as figuras a partir dos resultados:

```
python src/ataques/graficos.py
```

Iniciar a aplicação demonstrável (por padrão no nível N5):

```
python src/app.py
```

A aplicação ficará disponível em `http://127.0.0.1:5000`. Para demonstrar uma camada específica,
defina a variável de ambiente `NIVEL_DEMO` com um valor de 0 a 5 antes de iniciar:

```
NIVEL_DEMO=3 python src/app.py
```

## Resultados

Os resultados completos encontram-se em `resultados/resultados.json` e nas figuras em
`docs/figuras/`. A progressão observada confirma a hipótese do trabalho: a cada camada
adicionada, uma família de ataque adicional passa a ser bloqueada, até o bloqueio integral dos
acessos indevidos simulados na configuração completa (N5).

## Aviso

Este é um protótipo acadêmico, concebido como prova de conceito em ambiente controlado. A camada
FIDO2/WebAuthn é representada por sua propriedade de vinculação de origem, e não por uma
implementação criptográfica completa de WebAuthn. O código não se destina a uso em produção sem
revisão de segurança adicional.

## Como citar

Consulte o arquivo `CITATION.cff`. Referência sugerida:

> SANTOS, D. G. dos; VIEIRA, E. de S.; ALMEIDA, J. C. S. de; SILVA, J. P. B. da;
> CUNHA, S. A. N. da. Segurança de Dados em Aplicações Web: protótipo de defesa em profundidade
> com Zero Trust e autenticação multifatorial. Trabalho de Conclusão de Curso (Bacharelado em
> Sistemas de Informação) — Centro Universitário Braz Cubas, 2026.

## Licença

Distribuído sob a licença MIT. Consulte o arquivo `LICENSE`.
