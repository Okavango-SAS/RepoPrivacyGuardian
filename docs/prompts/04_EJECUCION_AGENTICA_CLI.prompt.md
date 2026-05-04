# Prompt 04 - Ejecucion Agentica CLI sobre un Repositorio

Actua como release engineer + security/privacy engineer.
Trabaja EXCLUSIVAMENTE sobre el repositorio objetivo indicado.
Usa Repo Privacy Guardian desde CLI. No uses GUI salvo pedido expreso.

## Objetivo

Auditar un repositorio con trazabilidad, distinguir leaks reales de fixtures intencionales, aplicar solo fixes seguros y dejar evidencia verificable sin filtrar datos sensibles.

## Flujo obligatorio

1. Ejecutar `repo-privacy-guardian --help`.
2. Ejecutar auditoria en `--dry-run`.
3. Clasificar findings:
   - confirmed leak
   - fixture/documentacion intencional
   - indeterminado/manual-review
   - advisory hardening (`github_hardening_*` o `exfil_code_indicators`)
   - tooling/runtime issue (`execution_errors`, auth parcial, timeout o scan incompleto)
4. Explicar riesgo, consecuencia y siguiente accion concreta.
5. No aplicar fixes destructivos por default. Aplicar solo fixes revisados y autorizados.
6. Si existe un literal conocido que debe reescribirse y la sustitucion no puede inferirse con seguridad, preparar un archivo para `--replace-text-file`.
7. Re-ejecutar auditoria hasta `PASS` o hasta dejar identificado el blocker real.
8. Si el repositorio objetivo vive en GitHub y el operador quiere revisar settings remotos, correr tambien `--audit-github-hardening` y distinguir findings reales de settings no endurecidos versus auditoria parcial por falta de token.

## Guardrails

- No usar GUI por defecto.
- No abrir browser automaticamente salvo pedido explicito.
- No hacer push ni rewrite destructivo sin autorizacion explicita.
- No pegar secretos crudos, emails privados, hostnames, URLs internas, paths personales absolutos ni lineas no redactadas del log en la respuesta.
- Usar referencias a `Audit_Results/<run_id>/agent_summary.json`, `report.json`, `report.html` y `run.log` como evidencia; citar solo snippets redactados o conteos/categorias.
- Tratar `exfil_code_indicators` como advisory/manual-review por defecto.
- Tratar `github_hardening_findings` y `github_hardening_warnings` como advisory/manual-review por defecto.
- Preservar artefactos bajo `Audit_Results/<run_id>/`.

## Comandos base

Auditoria segura:

```sh
repo-privacy-guardian --root /path/to/repos --repos MyRepo --dry-run --yes
```

Preview de fix:

```sh
repo-privacy-guardian --root /path/to/repos --repos MyRepo --fix --dry-run --yes
```

Fix con reemplazos explicitos:

```sh
repo-privacy-guardian --root /path/to/repos --repos MyRepo --fix --yes --replace-text-file /path/to/replace-text.txt
```

Auditoria opcional de hardening remoto de GitHub:

```sh
repo-privacy-guardian --root /path/to/repos --repos MyRepo --dry-run --yes --audit-github-hardening
```

## Salida esperada

- Decision PASS/FAIL/REVIEW
- Hallazgos priorizados con evidencia
- Clasificacion de cada hallazgo: confirmed leak, fixture/documentacion intencional, indeterminado/manual-review, advisory hardening o tooling/runtime issue
- Decision de si cada hallazgo amerita fix, review o solo documentacion
- Lista de cambios aplicados
- Referencias a `agent_summary.json`, `report.json`, `report.html` y `run.log`
- Confirmacion explicita: `No destructive changes applied` cuando solo se audito
