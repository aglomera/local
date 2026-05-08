"""
main.py — Loop principal do agente terminal.

Fluxo:
  1. Usuário digita objetivo
  2. LLM gera JSON com comandos
  3. Executor roda os comandos no shell
  4. Resultados são devolvidos ao LLM
  5. LLM decide se conclui ou gera novos comandos
  6. Repete até concluir, erro ou atingir MAX_ITERACOES
"""

import json
import sys

from llm import AgenteLLM
from executor import executar_lista

MAX_ITERACOES = 5  # limite de segurança para não esgotar cota


def exibir_pensamento(resposta: dict) -> None:
    """Exibe o pensamento do agente de forma destacada."""
    pensamento = resposta.get("pensamento", "")
    if pensamento:
        print(f"\n💭 Pensamento: {pensamento}")


def exibir_comandos(comandos: list[dict]) -> None:
    """Lista os comandos que serão executados."""
    print(f"\n📋 Comandos a executar ({len(comandos)}):")
    for item in comandos:
        print(f"   [{item.get('id', '?')}] {item.get('cmd')} — {item.get('descricao', '')}")


def loop_agente(objetivo: str) -> None:
    """
    Loop principal: inicializa o agente, itera até conclusão ou erro.
    """
    agente = AgenteLLM()
    print(f"\n🎯 Objetivo: {objetivo}")
    print("─" * 50)

    # --- Primeira chamada: LLM recebe o objetivo ---
    try:
        resposta = agente.primeira_chamada(objetivo)
    except Exception as e:
        print(f"\n❌ Erro na primeira chamada ao LLM: {e}")
        return

    for iteracao in range(1, MAX_ITERACOES + 1):
        print(f"\n🔄 Iteração {iteracao}/{MAX_ITERACOES}")
        exibir_pensamento(resposta)

        # --- Verifica se o agente sinalizou conclusão ou erro ---
        status = resposta.get("status")
        if status == "concluido":
            print(f"\n✅ Concluído!\n   {resposta.get('resumo', '')}")
            return
        if status == "erro":
            print(f"\n⚠️  Agente reportou erro:\n   {resposta.get('resumo', '')}")
            return

        # --- Obtém lista de comandos ---
        comandos = resposta.get("comandos")
        if not comandos:
            print("\n⚠️  Resposta inesperada do LLM (sem 'comandos' nem 'status').")
            print(f"   JSON recebido: {json.dumps(resposta, ensure_ascii=False)}")
            return

        exibir_comandos(comandos)
        print("\n⚙️  Executando...")

        # --- Executa os comandos no terminal ---
        resultados = executar_lista(comandos)

        # --- Devolve resultados ao LLM para avaliação ---
        try:
            resposta = agente.chamada_feedback(resultados)
        except Exception as e:
            print(f"\n❌ Erro ao chamar LLM para feedback: {e}")
            return

    # Atingiu o limite de iterações sem concluir
    print(f"\n⛔ Limite de {MAX_ITERACOES} iterações atingido sem conclusão.")
    print("   Verifique o estado do sistema manualmente.")


def main() -> None:
    print("=" * 50)
    print("  🤖 Agente Terminal — Gemma 3")
    print("=" * 50)
    print("Digite seu objetivo (ou 'sair' para encerrar).")

    while True:
        try:
            objetivo = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nEncerrando.")
            sys.exit(0)

        if not objetivo:
            continue
        if objetivo.lower() in {"sair", "exit", "quit"}:
            print("Até logo!")
            sys.exit(0)

        loop_agente(objetivo)
        print("\n" + "─" * 50)


if __name__ == "__main__":
    main()
