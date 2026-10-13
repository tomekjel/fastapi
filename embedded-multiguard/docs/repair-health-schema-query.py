#!/usr/bin/env python3
"""Narrow repair for the observed production /health SQL literal bug.

Run as root only in FastAPI CT 103. Does not deploy OWNER or alter its manifest.
Changes one SQL string, preserves a backup, verifies health JSON, and rolls back
if service restart or health validation fails.
"""
import ast
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess

OLD = "SELECT schema_name FROM information_schema.schemata WHERE schema_name IN (core,service,assist,breeze,config) ORDER BY schema_name"
NEW = "SELECT schema_name FROM information_schema.schemata WHERE schema_name IN ('core','service','assist','breeze','config') ORDER BY schema_name"
MAIN = Path('/opt/multiservis/app/main.py')
SERVICE = 'multiservis-api.service'
BACKUP_DIR = Path('/opt/multiservis/backups')


def repair_source(source):
    tree = ast.parse(source)
    handlers = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == 'health']
    if len(handlers) != 1:
        raise RuntimeError('STOP: expected exactly one health handler')
    constants = [n.value for n in ast.walk(handlers[0]) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    if NEW in constants and OLD not in constants:
        return source
    if constants.count(OLD) != 1 or source.count(OLD) != 1:
        raise RuntimeError('STOP: unexpected health query; no file changed')
    literal = next(n for n in ast.walk(handlers[0]) if isinstance(n, ast.Constant) and n.value == OLD)
    segment = ast.get_source_segment(source, literal)
    if not segment or source.count(segment) != 1:
        raise RuntimeError("STOP: ambiguous SQL literal")
    updated = source.replace(segment, repr(NEW), 1)
    compile(updated, str(MAIN), 'exec')
    normalized = ast.parse(updated)
    changed = 0
    for node in ast.walk(normalized):
        if isinstance(node, ast.Constant) and node.value == NEW:
            node.value = OLD
            changed += 1
    if changed != 1 or ast.dump(tree) != ast.dump(normalized):
        raise RuntimeError('STOP: change exceeds the single reviewed SQL string')
    return updated


def verify_health():
    result = subprocess.run(['curl', '--fail', '--silent', '--show-error', '--retry', '3', '--retry-delay', '2', '--retry-connrefused', '--max-time', '20', 'https://api.multi-servis.pl/health'], check=True, capture_output=True, text=True)
    health = json.loads(result.stdout)
    if health.get('status') != 'ok' or health.get('database') != 'connected':
        raise RuntimeError('Health JSON still reports an error')
    print('PASS: /health status=ok, database=connected; schemas=' + ','.join(health.get('schemas', [])))


def main():
    if os.geteuid() != 0 or not MAIN.is_file():
        raise RuntimeError('STOP: run as root inside FastAPI CT 103')
    subprocess.run(['systemctl', 'is-active', '--quiet', SERVICE], check=True)
    source = MAIN.read_text(encoding='utf-8')
    updated = repair_source(source)
    if updated == source:
        verify_health()
        print('ALREADY_FIXED: no file changed or service restarted')
        return
    backup_dir = BACKUP_DIR
    backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    backup = backup_dir / ('main-health-' + stamp + '.py')
    shutil.copy2(MAIN, backup)
    try:
        MAIN.write_text(updated, encoding='utf-8')
        subprocess.run(['systemctl', 'restart', SERVICE], check=True)
        verify_health()
    except Exception:
        shutil.copy2(backup, MAIN)
        subprocess.run(['systemctl', 'restart', SERVICE], check=True)
        print('ROLLBACK: previous main.py restored; backup=' + str(backup))
        raise
    print('SUCCESS: only health schema query repaired; backup=' + str(backup))


if __name__ == '__main__':
    main()
