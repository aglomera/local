"""
llm.py — Cliente LLM para comunicação com Ollama (local) via lib `ollama`.

Modelo padrão: huihui_ai/deepseek-r1-abliterated:7b-qwen-distill

ATENÇÃO SOBRE O DEEPSEEK-R1:
    O modelo emite blocos de raciocínio internos entre as tags <think>…</think>
    antes de gerar a resposta final. Esses blocos são filtrados automaticamente
    por `_remover_thinking()` para que o restante do sistema receba apenas JSON
    limpo, sem texto residual de raciocínio.

INSTALAÇÃO:
    pip install ollama
    ollama pull huihui_ai/deepseek-r1-abliterated:7b-qwen-distill

VARIÁVEIS DE AMBIENTE (opcionais):
    OLLAMA_HOST   — URL base do servidor (padrão: http://localhost:11434)
    OLLAMA_MODEL  — Nome do modelo (padrão: huihui_ai/deepseek-r1-abliterated:7b-qwen-distill)
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any

import ollama

logger = logging.getLogger("nexus.llm")

# ── Configuração ──────────────────────────────────────────────────────────────

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
NOME_MODELO = os.getenv(
    "OLLAMA_MODEL",
    "huihui_ai/deepseek-r1-abliterated:7b-qwen-distill",
)

# Cliente com host configurável via env
_cliente = ollama.Client(host=OLLAMA_HOST)


# ── Helpers internos ──────────────────────────────────────────────────────────

def _remover_thinking(texto: str) -> str:
    """
    Remove blocos <think>…</think> emitidos pelo DeepSeek-R1 antes da resposta.
    Preserva tudo o que vem APÓS o último </think>.
    """
    limpo = re.sub(r"<think>[\s\S]*?</think>", "", texto, flags=re.IGNORECASE)
    return limpo.strip()


def _montar_mensagens(prompt_sistema: str, mensagem_usuario: str) -> list[dict]:
    """
    Constrói a lista de mensagens no formato esperado pela lib ollama.
    """
    return [
        {"role": "system", "content": prompt_sistema},
        {"role": "user",   "content": mensagem_usuario},
    ]


# ── Interface pública ─────────────────────────────────────────────────────────

def chamar_llm(
    prompt_sistema: str,
    mensagem_usuario: str,
    temperatura: float = 0.2,
    max_tokens_saida: int = 1024,
    tentativas: int = 3,
    pausa_entre_tentativas: float = 2.0,
) -> str:
    """
    Envia uma requisição ao Ollama via lib nativa e retorna o texto da resposta
    já sem blocos <think>.

    A lib `ollama` não tem timeout fixo por HTTP — a inferência roda até
    completar, o que é o comportamento correto para modelos locais lentos.

    Parâmetros
    ----------
    prompt_sistema:
        Instrução de sistema (persona + regras de formato JSON).
    mensagem_usuario:
        Contexto atual da missão montado pelo nó chamador.
    temperatura:
        Criatividade da resposta (0.0–1.0). Valores baixos = mais determinístico.
    max_tokens_saida:
        Limite de tokens na resposta (num_predict no Ollama).
    tentativas:
        Número de re-tentativas em caso de erro de conexão.
    pausa_entre_tentativas:
        Segundos de espera entre tentativas (backoff linear).

    Retorna
    -------
    str
        Texto bruto da resposta, sem blocos <think>, pronto para parse JSON.

    Raises
    ------
    RuntimeError
        Se todas as tentativas falharem.
    """
    mensagens = _montar_mensagens(prompt_sistema, mensagem_usuario)

    for tentativa in range(1, tentativas + 1):
        try:
            logger.debug(
                "Chamada Ollama — tentativa %d/%d | modelo=%s",
                tentativa, tentativas, NOME_MODELO,
            )

            resposta = _cliente.chat(
                model=NOME_MODELO,
                messages=mensagens,
                options={
                    "temperature": temperatura,
                    "num_predict": max_tokens_saida,
                },
            )

            texto_bruto = resposta["message"]["content"].strip()
            texto_limpo = _remover_thinking(texto_bruto)

            logger.debug(
                "Resposta recebida (%d chars brutos, %d chars limpos).",
                len(texto_bruto), len(texto_limpo),
            )
            return texto_limpo

        except ollama.ResponseError as exc:
            # Erro retornado pelo servidor Ollama (ex: modelo não encontrado)
            logger.warning(
                "Ollama ResponseError (tentativa %d/%d): %s",
                tentativa, tentativas, exc,
            )
            # Se o modelo não existe, não adianta tentar de novo
            if "not found" in str(exc).lower():
                raise RuntimeError(
                    f"Modelo '{NOME_MODELO}' não encontrado no Ollama. "
                    f"Execute: ollama pull {NOME_MODELO}"
                ) from exc

        except Exception as exc:
            # Cobre falhas de conexão, servidor fora do ar, etc.
            logger.warning(
                "Erro na chamada ao Ollama (tentativa %d/%d): %s\n"
                "  → Certifique-se de que o Ollama está rodando: `ollama serve`",
                tentativa, tentativas, exc,
            )

        if tentativa < tentativas:
            espera = pausa_entre_tentativas * tentativa
            logger.debug("Aguardando %.1fs antes da próxima tentativa...", espera)
            time.sleep(espera)

    raise RuntimeError(
        f"Falha ao chamar o Ollama após {tentativas} tentativas. "
        f"Verifique se o serviço está ativo em {OLLAMA_HOST} "
        f"e se o modelo '{NOME_MODELO}' foi baixado com:\n"
        f"  ollama pull {NOME_MODELO}"
    )


def parsear_json_resposta(texto: str) -> dict[str, Any]:
    """
    Faz o parse seguro de uma resposta JSON do LLM.

    Pipeline de limpeza:
        1. Remoção de blocos <think> residuais (segurança extra)
        2. Tentativa de parse direto
        3. Remoção de blocos de código markdown (```json … ```)
        4. Extração via regex do primeiro objeto JSON encontrado

    Raises
    ------
    ValueError
        Se nenhuma estratégia conseguir produzir JSON válido.
    """
    # Segurança extra: garante que nenhum <think> escapou
    texto = _remover_thinking(texto).strip()

    # 1. Tentativa direta
    try:
        return json.loads(texto)
    except json.JSONDecodeError:
        pass

    # 2. Remove blocos de código markdown
    texto_limpo = re.sub(r"```(?:json)?\s*", "", texto).replace("```", "").strip()
    try:
        return json.loads(texto_limpo)
    except json.JSONDecodeError:
        pass

    # 3. Extração via regex do primeiro objeto JSON encontrado
    correspondencia = re.search(r"\{[\s\S]*\}", texto_limpo)
    if correspondencia:
        try:
            return json.loads(correspondencia.group())
        except json.JSONDecodeError:
            pass

    logger.error("Não foi possível parsear JSON da resposta: %r", texto[:200])
    raise ValueError(f"Resposta do LLM não é JSON válido: {texto[:200]!r}")