"""
principal.py — Ponto de entrada do Nexus Sentinela (v2 — Multi-Agentes).

Interface de terminal com progresso em tempo real via streaming do LangGraph.
Exibe cada transição de nó, agente ativo, fase IER, comandos e resumo final
com painel de vulnerabilidades e RCA.

Por padrão roda sem limites de iteração, timeout ou erros consecutivos —
o agente para apenas quando o Supervisor ou Auditor sinalizarem conclusão.

Uso:
    python principal.py "Enumerar portas abertas em 127.0.0.1"
    python principal.py "Auditar aplicação web em http://alvo.local"
    python principal.py --ajuda
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import textwrap
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))

from estado import criar_estado_inicial
from grafo import obter_grafo


# ── Paleta de cores ANSI ──────────────────────────────────────────────────────
class Cor:
    RESET      = "\033[0m"
    NEGRITO    = "\033[1m"
    VERMELHO   = "\033[91m"
    VERDE      = "\033[92m"
    AMARELO    = "\033[93m"
    AZUL       = "\033[94m"
    MAGENTA    = "\033[95m"
    CIANO      = "\033[96m"
    BRANCO     = "\033[97m"
    CINZA      = "\033[90m"
    LARANJA    = "\033[33m"
    ROXO       = "\033[35m"


# ── Mapeamento visual dos nós ─────────────────────────────────────────────────

_PREFIXO_NOS = {
    "no_supervisor":              f"{Cor.CIANO}[SUPERVISOR  ]{Cor.RESET}",
    "no_agente_reconhecimento":   f"{Cor.AZUL}[RECON       ]{Cor.RESET}",
    "no_agente_web":              f"{Cor.VERDE}[WEB         ]{Cor.RESET}",
    "no_agente_infra_ad":         f"{Cor.LARANJA}[INFRA/AD    ]{Cor.RESET}",
    "no_agente_pwn":              f"{Cor.ROXO}[PWN         ]{Cor.RESET}",
    "no_executor":                f"{Cor.AMARELO}[EXECUTOR    ]{Cor.RESET}",
    "no_auditor":                 f"{Cor.MAGENTA}[AUDITOR     ]{Cor.RESET}",
}

_COR_SEVERIDADE = {
    "info":    Cor.CINZA,
    "baixa":   Cor.AZUL,
    "media":   Cor.AMARELO,
    "alta":    Cor.LARANJA,
    "critica": Cor.VERMELHO,
}

_COR_FASE = {
    "identify": Cor.AZUL,
    "exploit":  Cor.LARANJA,
    "report":   Cor.VERDE,
}


# ── Helpers de exibição ───────────────────────────────────────────────────────

def _cabecalho() -> None:
    print(f"""
{Cor.VERMELHO}{Cor.NEGRITO}
 ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗
 ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝
 ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗
 ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║
 ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║
 ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
{Cor.CIANO}  SENTINELA v2 — Multi-Agentes Red Team (LangGraph){Cor.RESET}
{Cor.CINZA}  Apenas para ambientes autorizados e fins educacionais.{Cor.RESET}
""")


def _separador(titulo: str = "", largura: int = 72) -> None:
    if titulo:
        lado = (largura - len(titulo) - 2) // 2
        linha = f"{Cor.CINZA}{'─' * lado} {Cor.CIANO}{titulo}{Cor.CINZA} {'─' * lado}{Cor.RESET}"
    else:
        linha = f"{Cor.CINZA}{'─' * largura}{Cor.RESET}"
    print(linha)


def _tag_fase(fase: str) -> str:
    cor = _COR_FASE.get(fase, Cor.BRANCO)
    return f"{cor}[{fase.upper()}]{Cor.RESET}"


def _exibir_evento_stream(nome_no: str, delta: dict) -> None:
    """Processa e exibe um evento de streaming do LangGraph."""
    ts = datetime.now().strftime("%H:%M:%S")
    prefixo = _PREFIXO_NOS.get(nome_no, f"{Cor.BRANCO}[{nome_no.upper()[:12]}]{Cor.RESET}")

    print(f"\n{Cor.CINZA}{ts}{Cor.RESET} {prefixo}", end="")

    if nome_no == "no_supervisor":
        agente = delta.get("agente_ativo", "?")
        fase = delta.get("fase_ier", "?")
        concluido = delta.get("concluido", False)
        if concluido:
            print(f"  {Cor.VERDE}✔ MISSÃO CONCLUÍDA — {delta.get('motivo_encerramento','')}{Cor.RESET}")
        else:
            print(f"  → {Cor.NEGRITO}{agente.upper()}{Cor.RESET} {_tag_fase(fase)}")

    elif nome_no in ("no_agente_reconhecimento", "no_agente_web",
                     "no_agente_infra_ad", "no_agente_pwn"):
        cmd = delta.get("ultimo_comando", "")
        iteracao = delta.get("contador_tentativas", "?")
        novas_techs = delta.get("tecnologias_detectadas", [])
        novas_vulns = delta.get("vulnerabilidades_potenciais", [])
        print(f"\n  {Cor.NEGRITO}Iteração:{Cor.RESET} {iteracao}")
        print(f"  {Cor.NEGRITO}Comando :{Cor.RESET}  {Cor.AMARELO}{cmd}{Cor.RESET}")
        if novas_techs:
            print(f"  {Cor.NEGRITO}Techs   :{Cor.RESET}  {Cor.CIANO}{', '.join(novas_techs)}{Cor.RESET}")
        if novas_vulns:
            for v in novas_vulns:
                sev = v.get("severidade", "info")
                cor_sev = _COR_SEVERIDADE.get(sev, Cor.BRANCO)
                print(f"  {cor_sev}⚑ [{sev.upper()}]{Cor.RESET} {v.get('descricao','')}")

    elif nome_no == "no_executor":
        saida = delta.get("ultimo_resultado", "")
        codigo = delta.get("ultimo_codigo_retorno", -1)
        duracao = delta.get("ultima_duracao", 0.0)
        instaladas = delta.get("ferramentas_verificadas", {})
        icone = f"{Cor.VERDE}✓{Cor.RESET}" if codigo == 0 else f"{Cor.VERMELHO}✗{Cor.RESET}"
        print(f"\n  Código: {icone} {codigo}  |  Duração: {duracao:.2f}s")
        if instaladas:
            recentes = [f for f, ok in instaladas.items() if ok][-3:]
            if recentes:
                print(f"  {Cor.CIANO}Instaladas:{Cor.RESET} {', '.join(recentes)}")
        linhas = saida.strip().splitlines()[:5]
        for linha in linhas:
            print(f"  {Cor.CINZA}│{Cor.RESET} {linha}")
        if len(saida.strip().splitlines()) > 5:
            print(f"  {Cor.CINZA}│ ... ({len(saida.splitlines())} linhas totais){Cor.RESET}")

    elif nome_no == "no_auditor":
        auditoria = delta.get("auditoria_atual", {})
        falhou = auditoria.get("falhou", False)
        rca = auditoria.get("analise_rca", "")
        sugestao = auditoria.get("sugestao", "")
        proximo_agente = auditoria.get("proximo_agente_sugerido", "")
        fase_rec = auditoria.get("fase_recomendada", "")
        erros = delta.get("erros_consecutivos", 0)
        status = f"{Cor.VERMELHO}FALHA{Cor.RESET}" if falhou else f"{Cor.VERDE}OK{Cor.RESET}"
        print(f"\n  Status: {status}  |  Erros consecutivos: {erros}")
        if rca and rca != "N/A":
            rca_fmt = textwrap.fill(rca, width=58, subsequent_indent="              ")
            print(f"  {Cor.VERMELHO}RCA     :{Cor.RESET} {rca_fmt}")
        if sugestao:
            sug_fmt = textwrap.fill(sugestao, width=58, subsequent_indent="              ")
            print(f"  {Cor.CIANO}Sugestão:{Cor.RESET} {sug_fmt}")
        if proximo_agente:
            print(f"  {Cor.CINZA}Próximo :{Cor.RESET}  {proximo_agente.upper()} {_tag_fase(fase_rec)}")

    else:
        print(f"\n  {delta}")


def _resumo_final(estado_final: dict) -> None:
    """Exibe o painel completo de resumo ao término da execução."""
    _separador("RESUMO FINAL")

    concluido = estado_final.get("concluido", False)
    motivo = estado_final.get("motivo_encerramento", "encerrado pelo usuário")
    iteracoes = estado_final.get("contador_tentativas", 0)
    historico = estado_final.get("historico_comandos", [])
    sucessos = sum(1 for r in historico if r.get("sucesso"))
    falhas = len(historico) - sucessos

    icone_status = (
        f"{Cor.VERDE}✔ CONCLUÍDO{Cor.RESET}"
        if concluido else
        f"{Cor.AMARELO}⏹ ENCERRADO{Cor.RESET}"
    )
    print(f"\n  Status final : {icone_status}")
    print(f"  Motivo       : {motivo or 'N/A'}")
    print(f"  Iterações    : {iteracoes}")
    print(f"  Comandos     : {Cor.VERDE}{sucessos} OK{Cor.RESET}  "
          f"{Cor.VERMELHO}{falhas} FALHA{Cor.RESET}")

    techs = estado_final.get("tecnologias_detectadas", [])
    if techs:
        _separador("TECNOLOGIAS DETECTADAS")
        for tech in techs:
            print(f"  {Cor.CIANO}◈{Cor.RESET} {tech}")

    vulns = estado_final.get("vulnerabilidades_potenciais", [])
    if vulns:
        _separador("VULNERABILIDADES IDENTIFICADAS")
        for v in vulns:
            sev = v.get("severidade", "info")
            cor_sev = _COR_SEVERIDADE.get(sev, Cor.BRANCO)
            print(
                f"  {cor_sev}⚑ [{sev.upper():8s}]{Cor.RESET} "
                f"[{v.get('agente','?')}] {v.get('descricao','')}"
            )
            if v.get("evidencia"):
                print(f"    {Cor.CINZA}↳ {v['evidencia'][:120]}{Cor.RESET}")

    rca_logs = estado_final.get("relatorio_rca", [])
    if rca_logs:
        _separador("ROOT CAUSE ANALYSIS (FALHAS)")
        for entrada in rca_logs:
            print(f"  {Cor.VERMELHO}▸{Cor.RESET} {entrada}")

    if historico:
        _separador("HISTÓRICO DE COMANDOS")
        for reg in historico:
            icone = (
                f"{Cor.VERDE}✓{Cor.RESET}"
                if reg.get("sucesso")
                else f"{Cor.VERMELHO}✗{Cor.RESET}"
            )
            agente_tag = f"{Cor.CINZA}[{reg.get('agente','?')[:8]}]{Cor.RESET}"
            fase_tag = _tag_fase(reg.get("fase_ier", "?"))
            print(
                f"  {icone} [{reg['iteracao']:02d}] {agente_tag} {fase_tag} "
                f"{Cor.AMARELO}{reg['comando'][:60]}{Cor.RESET}"
                f" {Cor.CINZA}({reg['duracao_segundos']:.2f}s){Cor.RESET}"
            )

    _separador()
    print()


# ── Fluxo principal ───────────────────────────────────────────────────────────

# ── Campos cujos valores se acumulam via operator.add ────────────────────────
_CAMPOS_ACUMULATIVOS = {
    "tecnologias_detectadas",
    "vulnerabilidades_potenciais",
    "relatorio_rca",
    "historico_comandos",
    "logs_terminal",
}


def _mesclar_estado(base: dict, delta: dict) -> dict:
    """
    Aplica um delta sobre o estado acumulado, concatenando listas nos campos
    Annotated[list, operator.add] em vez de sobrescrevê-las.
    """
    novo = dict(base)
    for chave, valor in delta.items():
        if chave in _CAMPOS_ACUMULATIVOS and isinstance(valor, list):
            novo[chave] = list(base.get(chave, [])) + valor
        else:
            novo[chave] = valor
    return novo


def _confirmar_encerramento(estado: dict) -> bool:
    """
    Pergunta ao usuário se ele quer de fato encerrar a missão.
    Retorna True se o usuário confirmar, False se quiser continuar.
    """
    motivo = estado.get("motivo_encerramento", "objetivo concluído")
    iteracoes = estado.get("contador_tentativas", 0)

    print(f"""
{Cor.AMARELO}{'═' * 72}{Cor.RESET}
{Cor.NEGRITO}{Cor.AMARELO}  ⚑  O agente sinalizou encerramento da missão.{Cor.RESET}
{Cor.CINZA}  Motivo    : {motivo}
  Iterações : {iteracoes}{Cor.RESET}
{Cor.AMARELO}{'═' * 72}{Cor.RESET}""")

    while True:
        try:
            resposta = input(
                f"  {Cor.NEGRITO}Encerrar agora?{Cor.RESET} "
                f"{Cor.CIANO}[s]{Cor.RESET}/sim  "
                f"{Cor.VERDE}[n]{Cor.RESET}/não (continuar missão): "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            return True  # Ctrl+C na pergunta = encerra

        if resposta in ("s", "sim", "y", "yes", ""):
            return True
        if resposta in ("n", "nao", "não", "no"):
            print(f"  {Cor.VERDE}↩ Retomando missão...{Cor.RESET}")
            return False
        print(f"  {Cor.AMARELO}Digite 's' para encerrar ou 'n' para continuar.{Cor.RESET}")


def _executar_uma_missao(
    objetivo: str,
    max_tentativas: int = 0,
    timeout: int = 360,
    max_erros: int = 0,
    modo_debug: bool = False,
) -> dict:
    """
    Executa uma única missão no grafo e retorna o estado final.

    Quando o agente sinaliza conclusão ou abortagem, pergunta ao usuário
    se deseja encerrar ou continuar. Se o usuário escolher continuar, o grafo
    é reiniciado a partir do estado acumulado (histórico preservado).
    """
    _separador("MISSÃO")
    print(f"\n  {Cor.NEGRITO}Objetivo:{Cor.RESET} {Cor.BRANCO}{objetivo}{Cor.RESET}")
    print()

    estado_corrente: dict = dict(criar_estado_inicial(
        objetivo=objetivo,
        max_tentativas=max_tentativas,
        timeout_execucao=timeout,
        max_erros_consecutivos=max_erros,
    ))

    grafo = obter_grafo()

    _separador("EXECUÇÃO")

    while True:
        # Garante que cada rodada começa com concluido=False
        estado_corrente["concluido"] = False
        estado_corrente["motivo_encerramento"] = ""

        usuario_quer_continuar = False  # será True se usuário recusar encerramento

        try:
            for evento in grafo.stream(estado_corrente, stream_mode="updates"):
                for nome_no, delta in evento.items():
                    _exibir_evento_stream(nome_no, delta)
                    estado_corrente = _mesclar_estado(estado_corrente, delta)

                    # Detecta sinalização de encerramento ANTES do grafo rotear p/ END
                    if delta.get("concluido") and not usuario_quer_continuar:
                        if not _confirmar_encerramento(estado_corrente):
                            # Usuário quer continuar: reseta flag, reinicia grafo
                            estado_corrente["concluido"] = False
                            estado_corrente["motivo_encerramento"] = ""
                            estado_corrente["erros_consecutivos"] = 0
                            usuario_quer_continuar = True
                            # O stream atual vai até END naturalmente; não há como
                            # redirecionar. Aguardamos o fim do stream e reiniciamos.

        except KeyboardInterrupt:
            raise

        except Exception as exc:
            print(f"\n{Cor.VERMELHO}Erro crítico durante execução: {exc}{Cor.RESET}")
            if modo_debug:
                import traceback
                traceback.print_exc()
            estado_corrente.setdefault("motivo_encerramento", f"erro crítico: {exc}")

        # Se o usuário pediu para continuar, reinicia o grafo com estado acumulado
        if usuario_quer_continuar:
            _separador("RETOMADA")
            print(f"  {Cor.VERDE}Missão retomada a partir da iteração "
                  f"{estado_corrente.get('contador_tentativas', 0)}{Cor.RESET}\n")
            continue  # volta ao início do while True

        break  # encerramento confirmado pelo usuário ou natural

    _resumo_final(estado_corrente)
    return estado_corrente


def _pedir_novo_objetivo(args) -> str | None:
    """Exibe o prompt de nova missão no modo interativo."""
    print(f"\n{Cor.CIANO}{'─' * 72}{Cor.RESET}")
    print(
        f"{Cor.NEGRITO}  Nova missão{Cor.RESET}  "
        f"{Cor.CINZA}('sair' para encerrar | "
        f"'!cfg --opcao val -- Objetivo' para reconfigurar){Cor.RESET}"
    )
    print(f"{Cor.CIANO}{'─' * 72}{Cor.RESET}\n")

    try:
        entrada = input(f"  {Cor.AMARELO}▶{Cor.RESET} Objetivo: ").strip()
    except EOFError:
        return None

    if not entrada or entrada.lower() in ("sair", "exit", "quit", "q"):
        return None

    if entrada.startswith("!cfg "):
        partes = entrada[5:].split(" -- ", 1)
        if len(partes) == 2:
            _aplicar_cfg_temporario(partes[0].strip(), args)
            return partes[1].strip()
        print(f"  {Cor.VERMELHO}Formato inválido. Use: !cfg --opcao valor -- Objetivo{Cor.RESET}")
        return _pedir_novo_objetivo(args)

    return entrada


def _aplicar_cfg_temporario(cfg_str: str, args) -> None:
    """Parseia flags de configuração e aplica em `args` para a próxima missão."""
    tokens = cfg_str.split()
    i = 0
    mapa = {
        "--max-tentativas": ("max_tentativas", int),
        "--timeout":        ("timeout",        int),
        "--max-erros":      ("max_erros",      int),
    }
    while i < len(tokens):
        flag = tokens[i]
        if flag in mapa and i + 1 < len(tokens):
            attr, tipo = mapa[flag]
            setattr(args, attr, tipo(tokens[i + 1]))
            print(f"  {Cor.CIANO}cfg:{Cor.RESET} {flag} = {tokens[i + 1]}")
            i += 2
        elif flag == "--debug":
            args.debug = True; i += 1
        elif flag == "--no-debug":
            args.debug = False; i += 1
        else:
            print(f"  {Cor.AMARELO}Flag desconhecida ignorada: {flag}{Cor.RESET}"); i += 1


# ── CLI ───────────────────────────────────────────────────────────────────────

def _construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nexus-sentinela",
        description=(
            "Nexus Sentinela v2 — Agente Multi-Especialistas de Red Team com LangGraph.\n"
            "Roda sem limites por padrão — para apenas quando o objetivo for atingido.\n"
            "Use apenas em ambientes controlados e autorizados."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
            Exemplos:
              python principal.py "Enumerar serviços em 127.0.0.1"
              python principal.py "Auditar aplicação web em http://alvo.local"
              python principal.py "Comprometer servidor SSH vulnerável" --debug
              python principal.py  # modo interativo

            Limites opcionais (0 = desativado, padrão):
              python principal.py "..." --max-tentativas 20
              python principal.py "..." --timeout 60
              python principal.py "..." --max-erros 5
        """),
    )
    parser.add_argument("objetivo", nargs="?", help="Descrição da tarefa.")
    parser.add_argument(
        "--max-tentativas", type=int, default=0, metavar="N",
        help="Limite de iterações (padrão: 0 = sem limite).",
    )
    parser.add_argument(
        "--timeout", type=int, default=360, metavar="SEG",
        help="Timeout por comando em segundos (padrão: 360 = 6 minutos; 0 = sem limite).",
    )
    parser.add_argument(
        "--max-erros", type=int, default=0, metavar="N",
        help="Erros consecutivos para abortar (padrão: 0 = desativado).",
    )
    parser.add_argument("--debug", action="store_true",
                        help="Exibe logs detalhados de cada nó.")
    return parser


def main() -> None:
    parser = _construir_parser()
    args = parser.parse_args()

    nivel_log = logging.DEBUG if args.debug else logging.WARNING
    logging.basicConfig(
        level=nivel_log,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    _cabecalho()

    if args.objetivo:
        objetivo_atual = args.objetivo
    else:
        print(f"{Cor.CINZA}  Digite o primeiro objetivo ou 'sair' para encerrar.{Cor.RESET}\n")
        try:
            objetivo_atual = input(f"  {Cor.AMARELO}▶{Cor.RESET} Objetivo: ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{Cor.AMARELO}Encerrando.{Cor.RESET}")
            sys.exit(0)
        if not objetivo_atual or objetivo_atual.lower() in ("sair", "exit", "quit", "q"):
            print(f"{Cor.AMARELO}Encerrando.{Cor.RESET}")
            sys.exit(0)

    while True:
        try:
            _executar_uma_missao(
                objetivo=objetivo_atual,
                max_tentativas=args.max_tentativas,
                timeout=args.timeout,
                max_erros=args.max_erros,
                modo_debug=args.debug,
            )
        except KeyboardInterrupt:
            print(f"\n\n{Cor.AMARELO}  Missão interrompida. Voltando ao menu.{Cor.RESET}")

        proximo = _pedir_novo_objetivo(args)
        if proximo is None:
            print(f"\n{Cor.CIANO}  Nexus Sentinela encerrado. Até a próxima operação.{Cor.RESET}\n")
            sys.exit(0)

        objetivo_atual = proximo


if __name__ == "__main__":
    main()