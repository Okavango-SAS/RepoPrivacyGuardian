# Prompt 06 - Preparacion de Entorno Agentica

Actua como release/security engineer.
Trabaja solo sobre el checkout local de Repo Privacy Guardian recien clonado.
Usa la CLI para preparar y validar el entorno. No audites otros repositorios todavia.

## Objetivo

Dejar Repo Privacy Guardian listo para ser usado desde una IDE agentica o coding agent como Codex, Claude Code, Antigravity, GitHub Copilot, Cursor, o herramientas equivalentes, sin hacer cambios destructivos ni instalar tooling del sistema sin aprobacion explicita.

## Flujo obligatorio

1. Leer `README.MD`, `AGENTS.MD` y `docs/DOGFOODING.md` de forma rapida para entender el contrato.
2. Confirmar version de Python y rama/estado de git.
3. Crear o reutilizar un entorno virtual local solo si es necesario y seguro en el contexto.
4. Instalar el paquete en modo local:
   - uso CLI minimo: `python -m pip install .`
   - uso GUI opcional: `python -m pip install ".[gui]"`
   - desarrollo/release: `python -m pip install ".[dev,gui,remediation]"`
5. Ejecutar:
   - `repo-privacy-guardian --help`
   - `repo-privacy-guardian --check-tooling`
6. Si estas preparando el repo para contribuir o release, ejecutar tambien:
   - `python scripts/check_release_contract.py`
   - `python -m pytest -q`
7. Si falta tooling, reportar el bloqueo y pedir aprobacion antes de usar `--install-missing-tools` o instalar dependencias de sistema.

## Guardrails

- No ejecutar `--fix`, `--push`, `--github-owner`, ni auditorias sobre otros repositorios en este prompt.
- No leer, imprimir ni pedir tokens. Usar solo variables de entorno o sesion `gh` ya configurada cuando un flujo posterior lo requiera.
- No abrir la GUI salvo pedido explicito.
- No borrar artefactos, caches, ramas ni archivos no rastreados sin autorizacion explicita.
- Mantener la salida breve y accionable.

## Salida esperada

```text
Environment readiness: PASS | REVIEW | FAIL
Commands run:
- ...

Tooling:
- git: ready | missing | warning
- gui extras: ready | optional | missing
- remediation extras: ready | optional | missing

Next recommended command:
- repo-privacy-guardian --root <repos-root> --repos <target-repo> --dry-run --yes

Notes:
- [bloqueos o warnings concretos]
```
