"""
nos.py — Implementação de todos os nós do grafo Nexus Sentinela (v2 — Multi-Agentes).

Nós disponíveis:
    - no_supervisor:              Orquestrador central — decide qual agente chamar
    - no_agente_reconhecimento:   Recon, varredura, DNS, OSINT
    - no_agente_web:              OWASP Top 10, fuzzing, SQLi, XSS
    - no_agente_infra_ad:         Escalonamento de privilégios, Active Directory
    - no_agente_pwn:              Exploração de binários, buffer overflow, shellcode
    - no_executor:                Executa comandos shell com preflight check
    - no_auditor:                 Analisa resultados, faz RCA, recomenda próximo passo
"""

from __future__ import annotations

import logging
import time
from typing import Any

from estado import EstadoSentinela, RegistroComando, ResultadoAuditoria, EntradaVulnerabilidade
from executor import executar_comando
from llm import chamar_llm, parsear_json_resposta
from prompts import (
    PROMPT_SISTEMA_SUPERVISOR,
    PROMPT_SISTEMA_RECONHECIMENTO,
    PROMPT_SISTEMA_WEB,
    PROMPT_SISTEMA_INFRA_AD,
    PROMPT_SISTEMA_PWN,
    PROMPT_SISTEMA_AUDITOR,
    montar_mensagem_supervisor,
    montar_mensagem_agente,
    montar_mensagem_auditor,
)

logger = logging.getLogger("nexus.nos")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe_get(estado: EstadoSentinela, chave: str, padrao: Any = None) -> Any:
    return estado.get(chave, padrao)


def _construir_entrada_vuln(
    iteracao: int,
    agente: str,
    vuln: dict,
) -> EntradaVulnerabilidade:
    return EntradaVulnerabilidade(
        iteracao=iteracao,
        agente=agente,
        descricao=vuln.get("descricao", ""),
        severidade=vuln.get("severidade", "info"),
        evidencia=vuln.get("evidencia", ""),
    )


# ── No_Supervisor ─────────────────────────────────────────────────────────────

def no_supervisor(estado: EstadoSentinela) -> dict:
    """
    Orquestrador central. Analisa o estado global e decide:
    - Qual agente especializado deve agir a seguir
    - Em qual fase IER estamos
    - Se a missão foi concluída
    """
    logger.debug("no_supervisor | iter=%d", estado.get("contador_tentativas", 0))

    try:
        mensagem = montar_mensagem_supervisor(dict(estado))
        resposta_raw = chamar_llm(
            prompt_sistema=PROMPT_SISTEMA_SUPERVISOR,
            mensagem_usuario=mensagem,
            temperatura=0.1,
            max_tokens_saida=512,
        )
        dados = parsear_json_resposta(resposta_raw)
    except Exception as exc:
        logger.error("no_supervisor falhou ao chamar LLM: %s", exc)
        # Fallback seguro: continua com reconhecimento
        return {
            "agente_ativo": "reconhecimento",
            "fase_ier": estado.get("fase_ier", "identify"),
            "status_atual": "supervisionando",
        }

    agente = dados.get("agente_selecionado", "reconhecimento")
    fase = dados.get("fase_ier", estado.get("fase_ier", "identify"))
    missao_concluida = dados.get("missao_concluida", False)
    motivo = dados.get("motivo_conclusao", "")

    if missao_concluida:
        logger.info("Supervisor sinalizou missão concluída: %s", motivo)
        return {
            "agente_ativo": agente,
            "fase_ier": fase,
            "concluido": True,
            "motivo_encerramento": motivo or "Supervisor sinalizou conclusão.",
            "status_atual": "concluido",
        }

    return {
        "agente_ativo": agente,
        "fase_ier": fase,
        "status_atual": "supervisionando",
    }


# ── Fábrica de nós de agente ──────────────────────────────────────────────────

def _no_agente_generico(
    estado: EstadoSentinela,
    nome_agente: str,
    prompt_sistema: str,
) -> dict:
    """
    Lógica compartilhada por todos os agentes especializados.
    Chama o LLM com o contexto do agente e prepara o próximo comando.
    """
    iteracao = estado.get("contador_tentativas", 0) + 1
    logger.debug("%s | iter=%d", nome_agente, iteracao)

    try:
        mensagem = montar_mensagem_agente(dict(estado), nome_agente)
        resposta_raw = chamar_llm(
            prompt_sistema=prompt_sistema,
            mensagem_usuario=mensagem,
            temperatura=0.2,
            max_tokens_saida=1024,
        )
        dados = parsear_json_resposta(resposta_raw)
    except Exception as exc:
        logger.error("%s falhou ao chamar LLM: %s", nome_agente, exc)
        return {
            "contador_tentativas": iteracao,
            "status_atual": "analisando",
            "ultimo_comando": f"# Erro ao gerar comando: {exc}",
            "erros_consecutivos": estado.get("erros_consecutivos", 0) + 1,
        }

    proximo_comando = dados.get("proximo_comando", "echo 'sem comando'")
    missao_concluida = dados.get("missao_concluida", False)
    motivo = dados.get("motivo_conclusao", "")

    # Acumula tecnologias detectadas pelo agente
    novas_techs: list[str] = dados.get("tecnologias_detectadas", [])

    # Acumula vulnerabilidades identificadas pelo agente
    vulns_raw: list[dict] = dados.get("vulnerabilidades_potenciais", [])
    novas_vulns: list[EntradaVulnerabilidade] = [
        _construir_entrada_vuln(iteracao, nome_agente, v) for v in vulns_raw
    ]

    delta: dict = {
        "contador_tentativas": iteracao,
        "agente_ativo": nome_agente,
        "status_atual": "analisando",
        "ultimo_comando": proximo_comando,
        "tecnologias_detectadas": novas_techs,
        "vulnerabilidades_potenciais": novas_vulns,
    }

    if missao_concluida:
        delta["concluido"] = True
        delta["motivo_encerramento"] = motivo or f"{nome_agente} sinalizou conclusão."
        logger.info("%s sinalizou missão concluída: %s", nome_agente, motivo)

    return delta


# ── Agentes especializados ────────────────────────────────────────────────────

def no_agente_reconhecimento(estado: EstadoSentinela) -> dict:
    return _no_agente_generico(estado, "reconhecimento", PROMPT_SISTEMA_RECONHECIMENTO)


def no_agente_web(estado: EstadoSentinela) -> dict:
    return _no_agente_generico(estado, "web", PROMPT_SISTEMA_WEB)


def no_agente_infra_ad(estado: EstadoSentinela) -> dict:
    return _no_agente_generico(estado, "infra_ad", PROMPT_SISTEMA_INFRA_AD)


def no_agente_pwn(estado: EstadoSentinela) -> dict:
    return _no_agente_generico(estado, "pwn", PROMPT_SISTEMA_PWN)


# ── No_Executor ───────────────────────────────────────────────────────────────

def no_executor(estado: EstadoSentinela) -> dict:
    """
    Executa o comando gerado pelo agente ativo.
    Usa preflight check e auto-instalação de ferramentas quando necessário.
    """
    comando = estado.get("ultimo_comando", "").strip()
    iteracao = estado.get("contador_tentativas", 0)
    agente = estado.get("agente_ativo", "desconhecido")
    fase = estado.get("fase_ier", "identify")
    timeout = estado.get("timeout_execucao", 30)

    logger.debug("no_executor | iter=%d | cmd=%r", iteracao, comando[:80])

    if not comando or comando.startswith("#"):
        # Comando vazio ou comentário — registra como falha leve
        registro = RegistroComando(
            iteracao=iteracao,
            agente=agente,
            fase_ier=fase,
            comando=comando or "(vazio)",
            saida="Nenhum comando para executar.",
            codigo_retorno=-1,
            sucesso=False,
            duracao_segundos=0.0,
        )
        return {
            "status_atual": "executando",
            "ultimo_resultado": "Nenhum comando para executar.",
            "ultimo_codigo_retorno": -1,
            "ultima_duracao": 0.0,
            "historico_comandos": [registro],
            "logs_terminal": [f"[iter {iteracao}] SKIP: {comando}"],
        }

    resultado = executar_comando(
        comando=comando,
        timeout=timeout,
        auto_instalar=True,
    )

    registro = RegistroComando(
        iteracao=iteracao,
        agente=agente,
        fase_ier=fase,
        comando=comando,
        saida=resultado.saida[:2000],   # Limita tamanho no histórico
        codigo_retorno=resultado.codigo_retorno,
        sucesso=resultado.sucesso,
        duracao_segundos=resultado.duracao_segundos,
    )

    # Atualiza mapa de ferramentas verificadas
    ferramentas_atuais: dict[str, bool] = dict(estado.get("ferramentas_verificadas", {}))
    for ferramenta in resultado.ferramentas_instaladas:
        ferramentas_atuais[ferramenta] = True

    log_entry = (
        f"[iter {iteracao}][{agente}] "
        f"{'OK' if resultado.sucesso else 'FAIL'} "
        f"({resultado.codigo_retorno}) "
        f"{resultado.duracao_segundos:.2f}s | {comando[:60]}"
    )

    return {
        "status_atual": "executando",
        "ultimo_resultado": resultado.saida,
        "ultimo_codigo_retorno": resultado.codigo_retorno,
        "ultima_duracao": resultado.duracao_segundos,
        "historico_comandos": [registro],
        "ferramentas_verificadas": ferramentas_atuais,
        "logs_terminal": [log_entry],
    }


# ── No_Auditor ────────────────────────────────────────────────────────────────

def no_auditor(estado: EstadoSentinela) -> dict:
    """
    Analisa o resultado da última execução.
    Faz Root Cause Analysis, detecta vulnerabilidades e recomenda próximo passo.
    """
    iteracao = estado.get("contador_tentativas", 0)
    agente = estado.get("agente_ativo", "desconhecido")
    erros_consecutivos = estado.get("erros_consecutivos", 0)
    max_erros = estado.get("max_erros_consecutivos", 3)

    logger.debug("no_auditor | iter=%d", iteracao)

    try:
        mensagem = montar_mensagem_auditor(dict(estado))
        resposta_raw = chamar_llm(
            prompt_sistema=PROMPT_SISTEMA_AUDITOR,
            mensagem_usuario=mensagem,
            temperatura=0.1,
            max_tokens_saida=1024,
        )
        dados = parsear_json_resposta(resposta_raw)
    except Exception as exc:
        logger.error("no_auditor falhou ao chamar LLM: %s", exc)
        # Fallback: assume que falhou, não aborta
        auditoria = ResultadoAuditoria(
            falhou=True,
            motivo_falha=f"Auditor falhou ao processar: {exc}",
            sugestao="Tente novamente com o mesmo agente.",
            deve_abortar=False,
            analise_rca=f"Erro interno do auditor: {exc}",
            fase_recomendada=estado.get("fase_ier", "identify"),
            proximo_agente_sugerido=agente,
        )
        return {
            "status_atual": "auditando",
            "auditoria_atual": auditoria,
            "erros_consecutivos": erros_consecutivos + 1,
        }

    falhou = dados.get("falhou", False)
    deve_abortar = dados.get("deve_abortar", False)

    auditoria = ResultadoAuditoria(
        falhou=falhou,
        motivo_falha=dados.get("motivo_falha", "nenhuma"),
        sugestao=dados.get("sugestao", ""),
        deve_abortar=deve_abortar,
        analise_rca=dados.get("analise_rca", "N/A"),
        fase_recomendada=dados.get("fase_recomendada", "identify"),
        proximo_agente_sugerido=dados.get("proximo_agente_sugerido", "reconhecimento"),
    )

    # Acumula vulnerabilidades encontradas pelo auditor
    vulns_raw: list[dict] = dados.get("vulnerabilidades_encontradas", [])
    novas_vulns: list[EntradaVulnerabilidade] = [
        _construir_entrada_vuln(iteracao, f"auditor/{agente}", v) for v in vulns_raw
    ]

    # Atualiza contador de erros consecutivos
    if falhou:
        novo_erros = erros_consecutivos + 1
    else:
        novo_erros = 0  # Reset ao ter sucesso

    # Acumula RCA se houve falha
    novas_rcas: list[str] = []
    rca = auditoria["analise_rca"]
    if falhou and rca and rca != "N/A":
        novas_rcas.append(f"[iter {iteracao}][{agente}] {rca}")

    # Verifica se deve abortar por erros excessivos
    delta: dict = {
        "status_atual": "auditando",
        "auditoria_atual": auditoria,
        "erros_consecutivos": novo_erros,
        "vulnerabilidades_potenciais": novas_vulns,
        "relatorio_rca": novas_rcas,
    }

    if deve_abortar:
        delta["concluido"] = True
        delta["motivo_encerramento"] = (
            f"Auditor sinalizou abortagem: {auditoria['motivo_falha']}"
        )
        logger.warning("Auditor sinalizou ABORTAR: %s", auditoria["motivo_falha"])

    elif novo_erros >= max_erros:
        delta["concluido"] = True
        delta["motivo_encerramento"] = (
            f"Limite de {max_erros} erros consecutivos atingido."
        )
        logger.warning("Abortando por %d erros consecutivos.", novo_erros)

    return delta