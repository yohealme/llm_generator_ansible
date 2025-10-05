import os
import re
import shlex
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastmcp import FastMCP
import yaml
import requests
import paramiko


def _slugify_filename(name: str) -> str:
    """Создать безопасное имя файла из произвольной строки."""
    base = name.strip().lower()
    base = re.sub(r"[^a-z0-9\-_. ]+", "", base)
    base = re.sub(r"\s+", "-", base)
    return base or "playbook"


def _ensure_extension(file_name: str) -> str:
    if not file_name.lower().endswith((".yml", ".yaml")):
        return f"{file_name}.yml"
    return file_name


def _next_available_path(directory: Path, desired_name: str) -> Path:
    """Найти доступный путь: file, file-1, file-2, ..."""
    candidate = directory / desired_name
    if not candidate.exists():
        return candidate
    stem = candidate.stem
    suffix = candidate.suffix
    counter = 1
    while True:
        alt = directory / f"{stem}-{counter}{suffix}"
        if not alt.exists():
            return alt
        counter += 1


# OpenAI удалён по требованию: используем только Ollama или запасной шаблон


def _generate_with_ollama(prompt: str, hosts: str, become: bool) -> Optional[str]:
    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    model = os.getenv("OLLAMA_MODEL", "llama3.1")

    system = (
        "You are an expert DevOps engineer. Produce ONLY valid Ansible playbook YAML. "
        "One document array with a single play. No prose. No code fences."
    )
    user = (
        f"Description: {prompt}\n\n"
        f"Requirements: Generate a minimal, valid Ansible playbook. Use hosts: {hosts}. "
        f"become: {'true' if become else 'false'}. Add tasks with correct modules and arguments."
    )

    try:
        resp = requests.post(
            f"{base_url}/api/chat",
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "options": {"temperature": 0.2},
                "stream": False,
            },
            timeout=120,
        )
        resp.raise_for_status()
        data = resp.json()
        text = (data.get("message") or {}).get("content") or ""
        text = text.strip().strip("`")
        if text.startswith("yaml"):
            text = text[4:].strip()
        return text
    except Exception:
        return None


def _generate_with_llm(description: str, hosts: str, become: bool) -> Optional[str]:
    # Единственный провайдер — Ollama; если не доступен, вернём None и сработает fallback
    return _generate_with_ollama(description, hosts, become)


def _fallback_playbook(prompt: str, hosts: str, become: bool) -> str:
    """Запасной корректный минимальный playbook, если LLM недоступна."""
    play = [
        {
            "name": f"Generated from request: {prompt[:60]}".strip(),
            "hosts": hosts,
            "become": bool(become),
            "gather_facts": False,
            "tasks": [
                {
                    "name": "Echo request",
                    "debug": {"msg": prompt},
                }
            ],
        }
    ]
    return yaml.safe_dump(play, sort_keys=False, allow_unicode=True)


def generate_playbook_yaml(description: str, hosts: str, become: bool) -> str:
    text = _generate_with_llm(description, hosts, become)
    if not text:
        return _fallback_playbook(description, hosts, become)
    # Валидация YAML; при ошибке — безопасный откат
    try:
        data = yaml.safe_load(text)
        if not isinstance(data, list):
            raise ValueError("Expected a YAML list at top-level")
        return yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
    except Exception:
        return _fallback_playbook(description, hosts, become)


load_dotenv()
mcp = FastMCP("Ansible Playbook Server")


def generate_and_save_playbook_impl(
    description: str,
    file_name: Optional[str] = None,
    hosts: str = "all",
    become: bool = True,
    overwrite: bool = False,
) -> dict:
    """
    Сгенерировать Ansible playbook по текстовому описанию и сохранить на диск.

    Returns: { "path": str, "bytes": int, "validated": bool, "hosts": str }
    """
    output_dir = Path(os.getenv("PLAYBOOKS_DIR", "playbooks")).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if not file_name:
        file_name = _slugify_filename(description[:80])
    else:
        # Используем имя пользователя как есть, убирая путь
        file_name = os.path.basename(file_name.strip())
    file_name = _ensure_extension(file_name)

    path = output_dir / file_name
    if path.exists() and not overwrite:
        path = _next_available_path(output_dir, file_name)

    yaml_text = generate_playbook_yaml(description, hosts, become)

    validated = True
    try:
        yaml.safe_load(yaml_text)
    except Exception:
        validated = False

    with path.open("w", encoding="utf-8", newline="\n") as f:
        f.write(yaml_text)

    return {
        "path": str(path),
        "bytes": len(yaml_text.encode("utf-8")),
        "validated": validated,
        "hosts": hosts,
        "become": bool(become),
    }


@mcp.tool()
def generate_and_save_playbook(
    description: str,
    file_name: Optional[str] = None,
    hosts: str = "all",
    become: bool = True,
    overwrite: bool = False,
) -> dict:
    return generate_and_save_playbook_impl(
        description=description,
        file_name=file_name,
        hosts=hosts,
        become=become,
        overwrite=overwrite,
    )


def _ssh_connect(
    hostname: str,
    username: str,
    private_key_path: str,
    port: int = 22,
    private_key_passphrase: Optional[str] = None,
    timeout_seconds: int = 30,
) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # Попробуем автоматическую загрузку ключа; при пароле используем passphrase
    try:
        pkey = None
        if private_key_path:
            try:
                pkey = paramiko.RSAKey.from_private_key_file(private_key_path, password=private_key_passphrase)
            except Exception:
                try:
                    pkey = paramiko.Ed25519Key.from_private_key_file(private_key_path, password=private_key_passphrase)
                except Exception:
                    pkey = None
        client.connect(
            hostname=hostname,
            port=port,
            username=username,
            pkey=pkey,
            key_filename=None if pkey is not None else private_key_path,
            timeout=timeout_seconds,
            banner_timeout=timeout_seconds,
            auth_timeout=timeout_seconds,
            allow_agent=True,
            look_for_keys=True,
        )
        return client
    except Exception:
        client.close()
        raise


def _ssh_run(ssh: paramiko.SSHClient, command: str, timeout_seconds: int = 600) -> dict:
    stdin, stdout, stderr = ssh.exec_command(command, get_pty=False, timeout=timeout_seconds)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    exit_status = stdout.channel.recv_exit_status()
    return {"returncode": exit_status, "stdout": out, "stderr": err, "cmd": command}


def _resolve_remote_path(ssh: paramiko.SSHClient, path: str) -> str:
    if path.startswith("~"):
        res = _ssh_run(ssh, "bash -lc 'printf %s \"$HOME\"'")
        home = res.get("stdout", "").strip() or "/root"
        return home + path[1:]
    return path


@mcp.tool()
def generate_upload_and_run_playbook(
    description: str,
    remote_host: str,
    remote_user: str,
    private_key_path: str,
    file_name: Optional[str] = None,
    hosts: str = "all",
    become: bool = True,
    overwrite: bool = False,
    remote_directory: str = "~/mcp_playbooks",
    inventory_remote_path: Optional[str] = None,
    inventory_inline: Optional[str] = None,
    limit: Optional[str] = None,
    check: bool = False,
    tags: Optional[str] = None,
    extra_vars: Optional[dict] = None,
    become_method: Optional[str] = None,
    become_user: Optional[str] = None,
    ssh_port: int = 22,
    private_key_passphrase: Optional[str] = None,
    timeout_seconds: int = 900,
) -> dict:
    """
    Сгенерировать playbook локально, загрузить на удалённый Linux-хост (контроллер с Ansible) по SSH и запустить.
    Требуется установленный ansible-playbook на удалённой машине.
    """
    # 1) Сгенерировать и сохранить локально
    result_local = generate_and_save_playbook_impl(
        description=description,
        file_name=file_name,
        hosts=hosts,
        become=become,
        overwrite=overwrite,
    )
    local_path = result_local["path"]

    # 2) Подключение по SSH
    ssh = _ssh_connect(
        hostname=remote_host,
        username=remote_user,
        private_key_path=private_key_path,
        port=ssh_port,
        private_key_passphrase=private_key_passphrase,
        timeout_seconds=30,
    )
    try:
        # 3) Проверка наличия ansible-playbook
        check_cmd = "command -v ansible-playbook >/dev/null 2>&1 || echo MISSING"
        chk = _ssh_run(ssh, check_cmd)
        if "MISSING" in chk.get("stdout", ""):
            return {
                "ok": False,
                "error": "ansible-playbook не найден на удалённом хосте",
                "remote": chk,
                "local_playbook": local_path,
            }

        # 4) Обеспечить директорию и вычислить пути
        remote_dir = _resolve_remote_path(ssh, remote_directory)
        _ssh_run(ssh, f"mkdir -p {shlex.quote(remote_dir)}")
        remote_playbook_path = f"{remote_dir}/{os.path.basename(local_path)}"

        # 5) Загрузка playbook
        sftp = ssh.open_sftp()
        try:
            sftp.put(local_path, remote_playbook_path)
        finally:
            sftp.close()

        # 6) Если inventory_inline задан, положим его во временный файл рядом
        inv_path_effective = inventory_remote_path
        tmp_inv_name = None
        if not inv_path_effective and inventory_inline:
            tmp_inv_name = "inventory.ini"
            inv_path_effective = f"{remote_dir}/{tmp_inv_name}"
            sftp2 = ssh.open_sftp()
            try:
                with sftp2.file(inv_path_effective, "w") as f:
                    f.write(inventory_inline)
            finally:
                sftp2.close()

        # 7) Сформировать команду ansible-playbook
        parts = ["ansible-playbook", shlex.quote(remote_playbook_path)]
        if inv_path_effective:
            parts += ["-i", shlex.quote(inv_path_effective)]
        if limit:
            parts += ["-l", shlex.quote(limit)]
        if check:
            parts.append("--check")
        if tags:
            parts += ["--tags", shlex.quote(tags)]
        if extra_vars:
            try:
                import json as _json
                parts += ["-e", shlex.quote(_json.dumps(extra_vars, ensure_ascii=False))]
            except Exception:
                parts += ["-e", shlex.quote(str(extra_vars))]
        if become:
            parts.append("-b")
        if become_method:
            parts += ["--become-method", shlex.quote(become_method)]
        if become_user:
            parts += ["--become-user", shlex.quote(become_user)]

        cmd = " ".join(parts)
        run_res = _ssh_run(ssh, cmd, timeout_seconds=timeout_seconds)

        # 8) Уборка временного inventory при необходимости
        if tmp_inv_name:
            _ssh_run(ssh, f"rm -f {shlex.quote(inv_path_effective)}")

        ok = run_res.get("returncode", 1) == 0
        return {
            "ok": ok,
            "local_playbook": local_path,
            "remote_playbook": remote_playbook_path,
            "cmd": run_res.get("cmd"),
            "stdout": run_res.get("stdout"),
            "stderr": run_res.get("stderr"),
            "returncode": run_res.get("returncode"),
        }
    finally:
        ssh.close()


if __name__ == "__main__":
    mcp.run()


