"""
grafo.py — Construção e compilação do StateGraph do Nexus Sentinela (v2 — Multi-Agentes).

Fluxo:
    START
      └→ no_supervisor ──────────────────────────────────────────────┐
           ├→ no_agente_reconhecimento ──┐                           │
           ├→ no_agente_web             ├→ no_executor → no_auditor ─┘
           ├→ no_agente_infra_ad        │
           ├→ no_agente_pwn             ┘
           └→ END (missão concluída ou Auditor sinalizou abortagem)

Limites de iteração/erros são opcionais (0 = sem limite).
O encerramento natural ocorre apenas quando Supervisor ou Auditor sinalizam.
"""

from __future__ import annotations

import logging
from typing import Literal

from langgraph.graph import END, START, StateGraph

from estado import EstadoSentinela
from nos import (
    no_agente_infra_ad,
    no_agente_pwn,
    no_agente_reconhecimento,
    no_agente_web,
    no_auditor,
    no_executor,
    no_supervisor,
)

logger = logging.getLogger("nexus.grafo")

# ── Constantes dos nós ────────────────────────────────────────────────────────
NÓ_SUPERVISOR   = "no_supervisor"
NÓ_RECON        = "no_agente_reconhecimento"
NÓ_WEB          = "no_agente_web"
NÓ_INFRA_AD     = "no_agente_infra_ad"
NÓ_PWN          = "no_agente_pwn"
NÓ_EXECUTOR     = "no_executor"
NÓ_AUDITOR      = "no_auditor"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _limite_atingido(estado: EstadoSentinela) -> bool:
    """
    Retorna True apenas se max_tentativas > 0 E o contador atingiu o limite.
    Com max_tentativas == 0 o agente nunca para por contagem.
    """
    limite = estado.get("max_tentativas", 0)
    if limite <= 0:
        return False
    return estado["contador_tentativas"] >= limite


# ── Roteadores ────────────────────────────────────────────────────────────────

def _roteador_supervisor(
    estado: EstadoSentinela,
) -> Literal[
    "no_agente_reconhecimento",
    "no_agente_web",
    "no_agente_infra_ad",
    "no_agente_pwn",
    "__end__",
]:
    if estado.get("concluido", False):
        motivo = estado.get("motivo_encerramento", "objetivo concluído")
        logger.info("Roteador Supervisor → END | %s", motivo)
        return END

    if _limite_atingido(estado):
        logger.info("Roteador Supervisor → END | limite de iterações")
        return END

    agente = estado.get("agente_ativo", "reconhecimento")
    mapa = {
        "reconhecimento": NÓ_RECON,
        "web":            NÓ_WEB,
        "infra_ad":       NÓ_INFRA_AD,
        "pwn":            NÓ_PWN,
    }
    destino = mapa.get(agente, NÓ_RECON)
    logger.debug("Roteador Supervisor → %s | iter %d", destino,
                 estado["contador_tentativas"])
    return destino


def _roteador_pos_agente(
    estado: EstadoSentinela,
) -> Literal["no_executor", "__end__"]:
    if estado.get("concluido", False):
        logger.info("Roteador pós-agente → END | missão concluída sem execução")
        return END
    return NÓ_EXECUTOR


def _roteador_pos_auditoria(
    estado: EstadoSentinela,
) -> Literal["no_supervisor", "__end__"]:
    if estado.get("concluido", False):
        motivo = estado.get("motivo_encerramento", "N/A")
        logger.info("Roteador pós-auditoria → END | %s", motivo)
        return END

    if _limite_atingido(estado):
        logger.info("Roteador pós-auditoria → END | limite de iterações")
        return END

    logger.debug("Roteador pós-auditoria → Supervisor | iter %d",
                 estado["contador_tentativas"])
    return NÓ_SUPERVISOR


# ── Construção do grafo ───────────────────────────────────────────────────────

def construir_grafo() -> StateGraph:
    construtor = StateGraph(EstadoSentinela)

    construtor.add_node(NÓ_SUPERVISOR, no_supervisor)
    construtor.add_node(NÓ_RECON,     no_agente_reconhecimento)
    construtor.add_node(NÓ_WEB,       no_agente_web)
    construtor.add_node(NÓ_INFRA_AD,  no_agente_infra_ad)
    construtor.add_node(NÓ_PWN,       no_agente_pwn)
    construtor.add_node(NÓ_EXECUTOR,  no_executor)
    construtor.add_node(NÓ_AUDITOR,   no_auditor)

    construtor.add_edge(START, NÓ_SUPERVISOR)

    construtor.add_conditional_edges(
        NÓ_SUPERVISOR,
        _roteador_supervisor,
        {
            NÓ_RECON:    NÓ_RECON,
            NÓ_WEB:      NÓ_WEB,
            NÓ_INFRA_AD: NÓ_INFRA_AD,
            NÓ_PWN:      NÓ_PWN,
            END:         END,
        },
    )

    for no_agente in (NÓ_RECON, NÓ_WEB, NÓ_INFRA_AD, NÓ_PWN):
        construtor.add_conditional_edges(
            no_agente,
            _roteador_pos_agente,
            {NÓ_EXECUTOR: NÓ_EXECUTOR, END: END},
        )

    construtor.add_edge(NÓ_EXECUTOR, NÓ_AUDITOR)

    construtor.add_conditional_edges(
        NÓ_AUDITOR,
        _roteador_pos_auditoria,
        {NÓ_SUPERVISOR: NÓ_SUPERVISOR, END: END},
    )

    grafo_compilado = construtor.compile()
    logger.debug("Grafo compilado com sucesso.")
    return grafo_compilado


# ── Singleton do grafo ────────────────────────────────────────────────────────

_grafo: StateGraph | None = None


def obter_grafo() -> StateGraph:
    global _grafo
    if _grafo is None:
        _grafo = construir_grafo()
    return _grafo