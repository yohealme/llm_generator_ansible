## FastMCP Ansible Playbook Server

Этот сервер по протоколу Model Context Protocol (MCP) принимает текстовый запрос и генерирует Ansible playbook, сохраняя его на локальной машине.

### Установка

```bash
python -m venv .venv
.venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

Создайте файл `.env` (опционально):

```
PLAYBOOKS_DIR=playbooks
OLLAMA_MODEL=llama3.1
OLLAMA_BASE_URL=http://localhost:11434
```

> Если LLM недоступна, сервер сгенерирует корректный минимальный шаблон playbook (fallback).

### Запуск

Вариант 1 (через Python):

```bash
python server.py
```

Вариант 2 (через CLI fastmcp):

```bash
fastmcp run server.py
```

### Использование из MCP‑клиента

Подключите этот сервер в вашем MCP‑клиенте (например, Cursor/Continue/Cline/Claude Desktop) как внешний сервер по команде запуска `python server.py` (или `fastmcp run server.py`).

Сервер предоставляет инструмент `generate_and_save_playbook`:

- `description` (str): текстовый запрос/описание желаемого плейбука.
- `file_name` (str, optional): имя файла (без или с расширением). Если не указано — формируется автоматически.
- `hosts` (str, default: `all`): значение поля `hosts`.
- `become` (bool, default: `true`): включить привилегии sudo.
- `overwrite` (bool, default: `false`): перезаписывать существующий файл.

Возвращает JSON с путём к сохранённому файлу и служебной информацией.

### Структура вывода

Плейбуки сохраняются в директорию `PLAYBOOKS_DIR` (по умолчанию `playbooks`). Имя безопасно нормализуется, при конфликте добавляется суффикс `-1`, `-2`, ...

### Примечания

- Генерация по умолчанию выполняется локально через Ollama (`OLLAMA_MODEL`, `OLLAMA_BASE_URL`).
- Если генерация невозможна (нет ответа от модели), используется fallback-шаблон.

### Выбор LLM (Ollama / LLaMA)

1. Установите Ollama и скачайте модель:

```powershell
winget install Ollama.Ollama
ollama pull llama3.1
```

2. Установите переменные окружения (или добавьте в `.env`):

```powershell
$env:OLLAMA_MODEL = "llama3.1"
$env:OLLAMA_BASE_URL = "http://localhost:11434"
```

