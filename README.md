# Nexus Sentinela v2 — Multi-Agentes Red Team com LangGraph

> ⚠️ **Uso exclusivo em ambientes autorizados e para fins educacionais.**
> Operações ofensivas sem autorização explícita são ilegais.

## Visão Geral

O **Nexus Sentinela v2** é um sistema de Red Team autônomo construído sobre o
framework **LangGraph**, com uma arquitetura de **Multi-Agentes Especializados**
orquestrados por um **Supervisor** central. Cada agente possui uma persona e
conjunto de ferramentas alinhados ao *Roteiro de Progressão Técnica em
Auditoria de Segurança e Red Teaming*.

```
START
  └→ [Supervisor]
        ├→ [Agente Reconhecimento]  ─┐
        ├→ [Agente Web]              ├→ [Executor] → [Auditor] ─→ [Supervisor]
        ├→ [Agente Infra/AD]         │                                 │
        └→ [Agente Pwn]             ─┘                              END
```

---

## Estrutura do Projeto

```
nexus_sentinela/
├── principal.py    # Ponto de entrada CLI com UI de terminal
├── grafo.py        # StateGraph com Supervisor + 4 agentes especializados
├── nos.py          # Implementação de todos os nós (Supervisor, Agentes, Executor, Auditor)
├── estado.py       # TypedDict com campos IER, vulns, RCA e controle de agente
├── executor.py     # Execução de comandos com preflight check e auto-instalação
├── llm.py          # Cliente google-generativeai para Gemma-3-27b-it
├── prompts.py      # System prompts por agente + templates de mensagem
└── requirements.txt
```

---

## Instalação

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export GOOGLE_API_KEY="sua_chave_aqui"
```

---

## Uso

```bash
# Objetivo direto
python principal.py "Enumerar portas abertas em 127.0.0.1"

# Auditoria web completa
python principal.py "Auditar aplicação em http://alvo.local" --max-tentativas 20

# Análise de binário
python principal.py "Identificar vulnerabilidades no binário /opt/alvo/app" --timeout 60

# Modo interativo
python principal.py

# Com logs detalhados
python principal.py "Verificar configurações AD em 10.0.0.1" --debug
```

### Parâmetros da CLI

| Parâmetro          | Padrão | Descrição                                   |
|--------------------|--------|---------------------------------------------|
| `objetivo`         | —      | Descrição da tarefa a executar              |
| `--max-tentativas` | `15`   | Número máximo de iterações do loop          |
| `--timeout`        | `30`   | Timeout em segundos por comando             |
| `--max-erros`      | `3`    | Erros consecutivos máximos antes de abortar |
| `--debug`          | off    | Exibe logs internos de cada nó              |

---

## Arquitetura dos Agentes

### 🎯 No_Supervisor
- **Papel**: Orquestrador — decide qual agente chamar com base no contexto global
- **Entrada**: Estado completo (objetivo, histórico, fase IER, sugestão do auditor)
- **Saída**: `agente_ativo`, `fase_ier`, flag de conclusão
- **Temperatura**: 0.1 (decisões determinísticas)

### 🔍 Agente Reconhecimento *(Nível 1)*
- Varredura de portas/serviços: `nmap`, `masscan`
- Enumeração de DNS: `dnsrecon`, `dnsenum`, `fierce`
- OSINT: `theHarvester`, `whois`
- Fingerprinting de SO e serviços

### 🌐 Agente Web *(Nível 1–2)*
- OWASP Top 10: SQLi, XSS, SSRF, LFI, IDOR
- Fuzzing: `gobuster`, `ffuf`, `wfuzz`
- Análise de aplicações: `nikto`, `sqlmap`, `curl`
- Lógica de autenticação e controle de acesso

### 🏢 Agente Infra/AD *(Nível 2–3)*
- Escalonamento Linux: SUID, sudo, cron, capabilities
- Active Directory: Kerberoasting, AS-REP Roasting, Pass-the-Hash
- Enumeração AD: `crackmapexec`, `ldapsearch`, `enum4linux`, `bloodhound`
- Movimentação lateral via SMB/RPC

### 💀 Agente Pwn *(Nível 3)*
- Análise de binários: `objdump`, `strings`, `readelf`, `gdb`
- Exploração de memória: Stack/Heap overflow, Use-After-Free
- Bypass de proteções: ASLR, NX/DEP, Stack Canary, PIE
- Desenvolvimento de exploit com `pwntools`

### ⚡ No_Executor
- Executa qualquer comando com timeout configurável
- **Preflight check**: verifica disponibilidade de ferramentas antes de executar
- **Auto-instalação**: instala via `apt-get` ou `pip` quando necessário
- Rastreia ferramentas instaladas durante a sessão

### 🔬 No_Auditor
- Análise forense da saída com **Root Cause Analysis (RCA)**
- Classifica tipo de falha: sintaxe, permissão, dependência, lógica, rede
- Detecta vulnerabilidades na saída do comando
- Recomenda próximo agente e fase IER
- Único filtro de abortagem de segurança

---

## Metodologia IER

| Fase       | Descrição                                      | Agentes Típicos           |
|------------|------------------------------------------------|---------------------------|
| `identify` | Coleta de info, mapeamento, enumeração         | Reconhecimento, Web       |
| `exploit`  | Execução de explorações, escalonamento         | Web, Infra/AD, Pwn        |
| `report`   | Consolidação de achados, verificação evidências | Todos (modo leitura)      |

---

## Estado do Grafo (`EstadoSentinela`)

| Campo                     | Tipo                          | Descrição                              |
|---------------------------|-------------------------------|----------------------------------------|
| `agente_ativo`            | `str`                         | Agente atual (reconhecimento/web/...)  |
| `fase_ier`                | `str`                         | Fase identify/exploit/report           |
| `tecnologias_detectadas`  | `list[str]` (acumulativo)     | Stack do alvo identificada             |
| `vulnerabilidades_potenciais` | `list[EntradaVulnerabilidade]`| Achados acumulados com severidade  |
| `relatorio_rca`           | `list[str]` (acumulativo)     | Root Cause Analysis por falha          |
| `ferramentas_verificadas` | `dict[str, bool]`             | Resultado do preflight check           |
| `historico_comandos`      | `list[RegistroComando]`       | Todos os comandos com agente e fase    |
| `auditoria_atual`         | `ResultadoAuditoria`          | Parecer completo + RCA + recomendação  |

---

## Condições de Encerramento

O grafo para automaticamente quando:
1. O **Supervisor** sinaliza `missao_concluida: true`
2. O **Auditor** sinaliza `deve_abortar: true` (erro irrecuperável)
3. **Erros consecutivos** ≥ `max_erros_consecutivos`
4. **Iterações** ≥ `max_tentativas`
5. Usuário pressiona **Ctrl+C**

---

## Preflight Check — Ferramentas Suportadas

O executor verifica e pode instalar automaticamente mais de 30 ferramentas,
incluindo: `nmap`, `masscan`, `gobuster`, `ffuf`, `nikto`, `sqlmap`, `wfuzz`,
`crackmapexec`, `impacket`, `bloodhound`, `pwntools`, `gdb`, `enum4linux`, e mais.

Método de instalação configurado por ferramenta no catálogo interno de `executor.py`.
