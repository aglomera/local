"""
estado.py — Define o Estado Central do Grafo do Nexus Sentinela (v2 — Multi-Agentes).

Toda a memória de trabalho do sistema vive aqui. Cada nó lê e escreve
neste dicionário tipado; o LangGraph cuida da imutabilidade entre transições.

Novidades v2:
    - agente_ativo: qual especialista está no controle do ciclo atual
    - fase_ier: fase da metodologia Identify → Exploit → Report
    - tecnologias_detectadas: stack alvo acumulada ao longo da missão
    - vulnerabilidades_potenciais: achados acumulados de cada agente
    - relatorio_rca: Root Cause Analysis emitida pelo Auditor a cada falha
    - ferramentas_verificadas: mapa tool → disponível (preflight check)
"""

from __future__ import annotations

import operator
from typing import Annotated, Any

from typing_extensions import TypedDict


# ── Tipos auxiliares ──────────────────────────────────────────────────────────

class RegistroComando(TypedDict):
    """Representa uma entrada no histórico de execuções."""
    iteracao: int
    agente: str
    fase_ier: str
    comando: str
    saida: str
    codigo_retorno: int
    sucesso: bool
    duracao_segundos: float


class ResultadoAuditoria(TypedDict):
    """Parecer emitido pelo No_Auditor após cada execução."""
    falhou: bool
    motivo_falha: str
    sugestao: str
    deve_abortar: bool
    analise_rca: str
    fase_recomendada: str
    proximo_agente_sugerido: str


class EntradaVulnerabilidade(TypedDict):
    """Registro de uma vulnerabilidade identificada durante a missão."""
    iteracao: int
    agente: str
    descricao: str
    severidade: str    # "info" | "baixa" | "media" | "alta" | "critica"
    evidencia: str


# ── Estado Principal ──────────────────────────────────────────────────────────

class EstadoSentinela(TypedDict):
    """
    Estado imutável que percorre todo o grafo LangGraph.

    Campos com `Annotated[list, operator.add]` acumulam sem sobrescrever —
    padrão recomendado pelo LangGraph para mensagens e logs históricos.
    """

    # ── Configuração da missão ────────────────────────────────────────────────
    objetivo: str
    max_tentativas: int       # 0 = sem limite
    timeout_execucao: int     # segundos por comando (0 = sem timeout; padrão: 360)

    # ── Controle de agente ativo e fase IER ──────────────────────────────────
    agente_ativo: str
    fase_ier: str

    # ── Inteligência acumulada (acumulativa) ─────────────────────────────────
    tecnologias_detectadas: Annotated[list[str], operator.add]
    vulnerabilidades_potenciais: Annotated[list[EntradaVulnerabilidade], operator.add]
    relatorio_rca: Annotated[list[str], operator.add]

    # ── Memória de trabalho (acumulativa) ────────────────────────────────────
    historico_comandos: Annotated[list[RegistroComando], operator.add]
    logs_terminal: Annotated[list[str], operator.add]

    # ── Ferramentas (preflight) ───────────────────────────────────────────────
    ferramentas_verificadas: dict[str, bool]

    # ── Estado volátil (sobrescrito a cada iteração) ─────────────────────────
    contador_tentativas: int
    status_atual: str

    ultimo_comando: str
    ultimo_resultado: str
    ultimo_codigo_retorno: int
    ultima_duracao: float

    # ── Resultado da auditoria ────────────────────────────────────────────────
    auditoria_atual: ResultadoAuditoria

    # ── Controle de fluxo ────────────────────────────────────────────────────
    concluido: bool
    erros_consecutivos: int
    max_erros_consecutivos: int   # 0 = nunca aborta por erros consecutivos
    motivo_encerramento: str


# ── Fábrica de estado inicial ─────────────────────────────────────────────────

def criar_estado_inicial(
    objetivo: str,
    max_tentativas: int = 0,
    timeout_execucao: int = 360,
    max_erros_consecutivos: int = 0,
) -> EstadoSentinela:
    """
    Retorna um EstadoSentinela zerado, pronto para ser injetado no grafo.

    Todos os limites são desativados por padrão (valor 0 = sem restrição).
    O agente roda até o Supervisor ou Auditor sinalizarem conclusão/abortagem
    por razão técnica real, não por contador artificial.

    Parâmetros
    ----------
    objetivo:
        Descrição da tarefa que o agente deve executar.
    max_tentativas:
        Máximo de iterações (0 = ilimitado).
    timeout_execucao:
        Segundos máximos por comando (0 = sem timeout). Padrão: 360s (6 minutos).
    max_erros_consecutivos:
        Falhas seguidas para acionar encerramento (0 = desativado).
    """
    return EstadoSentinela(
        objetivo=objetivo,
        max_tentativas=max_tentativas,
        timeout_execucao=timeout_execucao,

        agente_ativo="reconhecimento",
        fase_ier="identify",

        tecnologias_detectadas=[],
        vulnerabilidades_potenciais=[],
        relatorio_rca=[],

        historico_comandos=[],
        logs_terminal=[],
        ferramentas_verificadas={},

        contador_tentativas=0,
        status_atual="inicializando",

        ultimo_comando="",
        ultimo_resultado="",
        ultimo_codigo_retorno=-1,
        ultima_duracao=0.0,

        auditoria_atual=ResultadoAuditoria(
            falhou=False,
            motivo_falha="",
            sugestao="",
            deve_abortar=False,
            analise_rca="N/A",
            fase_recomendada="identify",
            proximo_agente_sugerido="reconhecimento",
        ),

        concluido=False,
        erros_consecutivos=0,
        max_erros_consecutivos=max_erros_consecutivos,
        motivo_encerramento="",
    )