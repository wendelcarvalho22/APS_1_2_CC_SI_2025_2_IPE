# 🔐 APS — Criptografia RSA

**Atividades Práticas Supervisionadas (APS)** — Sistemas de Informação — UNIP
Disciplina vinculada: Introdução à Programação Estruturada (IPE)
Semestre: 2026/1

**Aluno:** Wendel Richard de Carvalho
**RA:** T2144I7
**Turma:** TT8P68

---

## 📋 Sobre o trabalho

Tema proposto pelo instrutivo: **"As Técnicas Criptográficas, Conceitos, Usos e Aplicações"**, aplicado a um cenário de controle de acesso seguro a um navio apreendido pela Guarda Costeira Brasileira, transportando resíduos tóxicos radioativos.

Técnica criptográfica escolhida: **RSA (Rivest–Shamir–Adleman)**, algoritmo de criptografia assimétrica.

O trabalho contempla:
- Fundamentação teórica completa sobre criptografia e RSA
- Implementação do algoritmo RSA em Python (sem bibliotecas externas)
- Interface gráfica desenvolvida com `tkinter`
- Demonstração de cifragem e decifragem de mensagens de até 128 caracteres
- Vídeo de apresentação com o programa em funcionamento

## 📁 Estrutura do repositório

```
.
├── README.md                          ← este arquivo
├── docs/
│   ├── APS_RSA_Criptografia.docx       ← trabalho escrito completo (Word)
│   └── Roteiro_Apresentacao.docx       ← roteiro e script do vídeo
├── codigo/
│   ├── rsa_tkinter.py                  ← programa principal (interface gráfica)
│   └── rsa_app.html                    ← versão web alternativa (mesmo algoritmo)
└── video/
    └── link_video.md                   ← link para o vídeo de apresentação
```

## 🚀 Como executar o programa

Pré-requisito: Python 3.8 ou superior (tkinter já vem incluído na instalação padrão).

```bash
git clone https://github.com/SEU-USUARIO/aps-rsa-criptografia.git
cd aps-rsa-criptografia/codigo
python3 rsa_tkinter.py
```

Alternativa sem instalar nada: abra `codigo/rsa_app.html` diretamente no navegador.


## 📚 Tecnologia utilizada

- **Python 3** — núcleo matemático do RSA (exponenciação modular, teste de primalidade de Miller-Rabin, algoritmo de Euclides estendido)
- **tkinter** — interface gráfica (biblioteca padrão do Python, sem dependências externas)
