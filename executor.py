"""
executor.py — Execução segura de comandos shell com preflight check e auto-instalação.

v2 — Novidades:
    - verificar_ferramenta(): checa se uma ferramenta está no PATH
    - instalar_ferramenta(): tenta instalar via apt-get ou pip
    - preflight_check(): verifica e opcionalmente instala uma lista de ferramentas
    - ResultadoExecucao agora inclui `ferramentas_instaladas` para rastreamento
"""

from __future__ import annotations

import logging
import shlex
import subprocess
import time
from dataclasses import dataclass, field

logger = logging.getLogger("nexus.executor")

# ── Mapeamento de ferramentas conhecidas ──────────────────────────────────────
# Mapa: nome_ferramenta → (método, pacote/módulo)
# método: "apt" | "pip" | "apt+pip" | "manual"
_CATALOGO_FERRAMENTAS: dict[str, tuple[str, str]] = {
    # Reconhecimento de rede
    "nmap":          ("apt",  "nmap"),
    "masscan":       ("apt",  "masscan"),
    "netcat":        ("apt",  "netcat-openbsd"),
    "nc":            ("apt",  "netcat-openbsd"),
    "whois":         ("apt",  "whois"),
    "dnsrecon":      ("pip",  "dnsrecon"),
    "dnsenum":       ("apt",  "dnsenum"),
    "fierce":        ("pip",  "fierce"),
    "theHarvester":  ("pip",  "theHarvester"),
    # Web
    "gobuster":      ("apt",  "gobuster"),
    "ffuf":          ("apt",  "ffuf"),
    "nikto":         ("apt",  "nikto"),
    "sqlmap":        ("pip",  "sqlmap"),
    "wfuzz":         ("pip",  "wfuzz"),
    "curl":          ("apt",  "curl"),
    "wget":          ("apt",  "wget"),
    "httpx":         ("pip",  "httpx"),
    # Infra / AD
    "enum4linux":    ("apt",  "enum4linux"),
    "smbclient":     ("apt",  "smbclient"),
    "rpcclient":     ("apt",  "samba-common-bin"),
    "crackmapexec":  ("pip",  "crackmapexec"),
    "ldapsearch":    ("apt",  "ldap-utils"),
    "impacket-secretsdump": ("pip", "impacket"),
    "bloodhound-python":    ("pip", "bloodhound"),
    # Exploração / Pwn
    "pwntools":      ("pip",  "pwntools"),
    "gdb":           ("apt",  "gdb"),
    "peda":          ("manual", "https://github.com/longld/peda"),
    "objdump":       ("apt",  "binutils"),
    "strings":       ("apt",  "binutils"),
    "ltrace":        ("apt",  "ltrace"),
    "strace":        ("apt",  "strace"),
    "metasploit":    ("manual", "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall && chmod 755 /tmp/msfinstall && /tmp/msfinstall"),
    # Utilidades gerais
    "python3":       ("apt",  "python3"),
    "pip3":          ("apt",  "python3-pip"),
    "git":           ("apt",  "git"),
    "jq":            ("apt",  "jq"),
}


# ── Resultado tipado ──────────────────────────────────────────────────────────

@dataclass
class ResultadoExecucao:
    """Encapsula tudo que o No_Executor precisa saber sobre uma execução."""
    comando: str
    saida: str
    codigo_retorno: int
    sucesso: bool
    duracao_segundos: float
    timeout_atingido: bool
    ferramentas_instaladas: list[str] = field(default_factory=list)


@dataclass
class ResultadoPreflight:
    """Resultado da verificação e instalação de ferramentas."""
    status: dict[str, bool]           # tool → disponível agora
    instaladas: list[str]             # ferramentas que foram instaladas com sucesso
    falhou_instalar: list[str]        # ferramentas cuja instalação falhou
    log: str                          # log textual do processo


# ── Preflight check ───────────────────────────────────────────────────────────

def verificar_ferramenta(nome: str) -> bool:
    """
    Verifica se uma ferramenta está disponível no PATH do sistema.

    Usa `which` e `command -v` como fallback para máxima compatibilidade.
    """
    try:
        resultado = subprocess.run(
            f"which {shlex.quote(nome)} 2>/dev/null || command -v {shlex.quote(nome)} 2>/dev/null",
            shell=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        disponivel = resultado.returncode == 0 and bool(resultado.stdout.strip())
        logger.debug("Ferramenta '%s': %s", nome, "disponível" if disponivel else "ausente")
        return disponivel
    except Exception as exc:
        logger.warning("Erro ao verificar ferramenta '%s': %s", nome, exc)
        return False


def instalar_ferramenta(nome: str, timeout: int = 120) -> tuple[bool, str]:
    """
    Tenta instalar uma ferramenta usando apt-get ou pip, conforme o catálogo.

    Retorna
    -------
    (sucesso: bool, log: str)
    """
    if nome not in _CATALOGO_FERRAMENTAS:
        return False, f"Ferramenta '{nome}' não está no catálogo de instalação."

    metodo, pacote = _CATALOGO_FERRAMENTAS[nome]
    logs = []

    try:
        if metodo == "apt":
            cmd = f"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {shlex.quote(pacote)} 2>&1"
            logs.append(f"[APT] Instalando {pacote}...")
            resultado = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            sucesso = resultado.returncode == 0
            logs.append(resultado.stdout[-500:] if resultado.stdout else "")
            if not sucesso:
                logs.append(f"[APT ERRO] {resultado.stderr[-300:]}")

        elif metodo == "pip":
            cmd = f"pip3 install --quiet --break-system-packages {shlex.quote(pacote)} 2>&1"
            logs.append(f"[PIP] Instalando {pacote}...")
            resultado = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            sucesso = resultado.returncode == 0
            logs.append(resultado.stdout[-500:] if resultado.stdout else "")
            if not sucesso:
                # Tenta sem --break-system-packages (ambientes mais antigos)
                cmd_alt = f"pip3 install --quiet {shlex.quote(pacote)} 2>&1"
                resultado = subprocess.run(cmd_alt, shell=True, capture_output=True, text=True, timeout=timeout)
                sucesso = resultado.returncode == 0

        elif metodo == "manual":
            logs.append(f"[MANUAL] '{nome}' requer instalação manual. Instruções: {pacote}")
            return False, "\n".join(logs)

        else:
            return False, f"Método de instalação '{metodo}' desconhecido."

        if sucesso:
            # Confirma disponibilidade pós-instalação
            disponivel = verificar_ferramenta(nome)
            sucesso = disponivel
            logs.append(f"[OK] '{nome}' {'disponível' if disponivel else 'ainda ausente após instalação'}.")
        else:
            logs.append(f"[FALHA] Instalação de '{nome}' falhou.")

        return sucesso, "\n".join(filter(None, logs))

    except subprocess.TimeoutExpired:
        return False, f"[TIMEOUT] Instalação de '{nome}' excedeu {timeout}s."
    except Exception as exc:
        return False, f"[ERRO] Falha inesperada ao instalar '{nome}': {exc}"


def preflight_check(
    ferramentas: list[str],
    auto_instalar: bool = True,
    timeout_instalacao: int = 120,
) -> ResultadoPreflight:
    """
    Verifica a disponibilidade de uma lista de ferramentas e, opcionalmente,
    tenta instalar as ausentes.

    Parâmetros
    ----------
    ferramentas:
        Lista de nomes de ferramentas a verificar (ex.: ["nmap", "gobuster"]).
    auto_instalar:
        Se True, tenta instalar ferramentas ausentes automaticamente.
    timeout_instalacao:
        Timeout em segundos para cada tentativa de instalação.

    Retorna
    -------
    ResultadoPreflight com status atualizado de cada ferramenta.
    """
    status: dict[str, bool] = {}
    instaladas: list[str] = []
    falhou_instalar: list[str] = []
    logs: list[str] = ["═══ PREFLIGHT CHECK ═══"]

    for nome in ferramentas:
        disponivel = verificar_ferramenta(nome)
        if disponivel:
            status[nome] = True
            logs.append(f"  ✓ {nome}")
            continue

        logs.append(f"  ✗ {nome} — ausente")

        if auto_instalar:
            logs.append(f"  ⟳ Tentando instalar {nome}...")
            sucesso, log_inst = instalar_ferramenta(nome, timeout=timeout_instalacao)
            logs.append(f"    {log_inst}")
            if sucesso:
                status[nome] = True
                instaladas.append(nome)
                logs.append(f"  ✓ {nome} — instalado com sucesso")
            else:
                status[nome] = False
                falhou_instalar.append(nome)
                logs.append(f"  ✗ {nome} — instalação falhou")
        else:
            status[nome] = False

    logs.append("═══════════════════════")
    return ResultadoPreflight(
        status=status,
        instaladas=instaladas,
        falhou_instalar=falhou_instalar,
        log="\n".join(logs),
    )


# ── Executor principal ────────────────────────────────────────────────────────

def executar_comando(
    comando: str,
    timeout: int = 360,
    shell: bool = True,
    diretorio_trabalho: str | None = None,
    ferramentas_requeridas: list[str] | None = None,
    auto_instalar: bool = True,
) -> ResultadoExecucao:
    """
    Executa um comando shell com preflight check opcional e retorna
    um ResultadoExecucao estruturado.

    Parâmetros
    ----------
    comando:
        String de comando a ser executada (ex.: "nmap -sV 192.168.1.1").
    timeout:
        Limite em segundos. Use 0 para sem limite. Padrão: 360s (6 minutos).
        Ferramentas como nmap, nikto e sqlmap podem demorar vários minutos.
    shell:
        Passa o comando para o shell do sistema.
    diretorio_trabalho:
        Diretório de trabalho do processo filho.
    ferramentas_requeridas:
        Lista de ferramentas a verificar/instalar antes da execução.
        Se None, inferidas automaticamente a partir do comando.
    auto_instalar:
        Se True, tenta instalar ferramentas ausentes via apt/pip.
    """
    logger.info("Executando: %s", comando)

    # ── Preflight ─────────────────────────────────────────────────────────────
    ferramentas_instaladas: list[str] = []
    if ferramentas_requeridas is None:
        ferramentas_requeridas = _inferir_ferramentas(comando)

    if ferramentas_requeridas:
        preflight = preflight_check(
            ferramentas_requeridas,
            auto_instalar=auto_instalar,
        )
        ferramentas_instaladas = preflight.instaladas
        logger.info("Preflight: %s", preflight.status)

        # Se uma ferramenta crítica está ausente e não foi instalada, reporta
        ferramentas_ausentes = [f for f, ok in preflight.status.items() if not ok]
        if ferramentas_ausentes:
            logger.warning("Ferramentas ausentes: %s", ferramentas_ausentes)

    # ── Execução ──────────────────────────────────────────────────────────────
    # timeout=0 significa "sem limite" — passa None ao subprocess para não
    # gerar TimeoutExpired imediatamente (comportamento do Python stdlib).
    timeout_subprocess: int | None = timeout if timeout > 0 else None
    inicio = time.monotonic()

    try:
        processo = subprocess.run(
            comando,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=timeout_subprocess,
            cwd=diretorio_trabalho,
            env=None,
        )
        duracao = time.monotonic() - inicio

        saida_combinada = _combinar_saidas(processo.stdout, processo.stderr)
        codigo = processo.returncode
        sucesso = _avaliar_sucesso(codigo, saida_combinada)

        logger.info(
            "Comando finalizado em %.2fs | código=%d | sucesso=%s",
            duracao, codigo, sucesso,
        )

        return ResultadoExecucao(
            comando=comando,
            saida=saida_combinada,
            codigo_retorno=codigo,
            sucesso=sucesso,
            duracao_segundos=duracao,
            timeout_atingido=False,
            ferramentas_instaladas=ferramentas_instaladas,
        )

    except subprocess.TimeoutExpired:
        duracao = time.monotonic() - inicio
        mensagem = f"[TIMEOUT] Comando excedeu {timeout_subprocess}s e foi interrompido."
        logger.warning(mensagem)
        return ResultadoExecucao(
            comando=comando,
            saida=mensagem,
            codigo_retorno=-1,
            sucesso=False,
            duracao_segundos=duracao,
            timeout_atingido=True,
            ferramentas_instaladas=ferramentas_instaladas,
        )

    except Exception as exc:
        duracao = time.monotonic() - inicio
        mensagem = f"[ERRO INTERNO] Falha ao executar comando: {exc}"
        logger.error(mensagem, exc_info=True)
        return ResultadoExecucao(
            comando=comando,
            saida=mensagem,
            codigo_retorno=-2,
            sucesso=False,
            duracao_segundos=duracao,
            timeout_atingido=False,
            ferramentas_instaladas=ferramentas_instaladas,
        )


# ── Helpers privados ──────────────────────────────────────────────────────────

def _combinar_saidas(stdout: str, stderr: str) -> str:
    """Junta stdout e stderr separados por uma linha divisória se ambos existirem."""
    partes = []
    if stdout and stdout.strip():
        partes.append(stdout.strip())
    if stderr and stderr.strip():
        partes.append(f"[STDERR]\n{stderr.strip()}")
    return "\n".join(partes) if partes else "(sem saída)"


_PADROES_ERRO_CRITICOS = (
    "permission denied",
    "command not found",
    "no such file or directory",
    "operation not permitted",
    "cannot open",
    "segmentation fault",
)


def _avaliar_sucesso(codigo_retorno: int, saida: str) -> bool:
    """
    Determina sucesso considerando código de retorno E padrões textuais.
    Um código 0 com mensagem de erro óbvia ainda é tratado como falha.
    """
    if codigo_retorno != 0:
        return False
    saida_lower = saida.lower()
    return not any(padrao in saida_lower for padrao in _PADROES_ERRO_CRITICOS)


def _inferir_ferramentas(comando: str) -> list[str]:
    """
    Extrai o nome do executável principal de um comando e verifica se ele
    está no catálogo de ferramentas conhecidas.

    Ex.: "nmap -sV 10.0.0.1" → ["nmap"]
    """
    if not comando or not comando.strip():
        return []
    # Pega o primeiro token do comando (antes de pipes, &&, etc.)
    primeiro = comando.strip().split()[0]
    # Remove caminhos absolutos
    nome = primeiro.split("/")[-1]
    return [nome] if nome in _CATALOGO_FERRAMENTAS else []