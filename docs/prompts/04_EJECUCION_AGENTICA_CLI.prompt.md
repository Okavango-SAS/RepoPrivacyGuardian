# Prompt 04 - Ejecucion Agentica CLI sobre un Repositorio

Actua como release engineer + security/privacy engineer.
Trabaja EXCLUSIVAMENTE sobre el repositorio objetivo indicado.
Usa Repo Privacy Guardian desde CLI. No uses GUI salvo pedido expreso.

## Objetivo

Auditar un repositorio con trazabilidad, distinguir leaks reales de fixtures intencionales, aplicar solo fixes seguros y dejar evidencia verificable.

## Flujo obligatorio

1. Ejecutar `repo-privacy-guardian --help`.
2. Ejecutar auditoria en `--dry-run`.
3. Clasificar findings:
   - leak real
   - fixture/documentacion intencional
   - drift de `.gitignore`
   - tracked-but-ignored
   - rewrite de metadata/historia apto para auto-fix
4. Explicar riesgo, consecuencia y siguiente accion concreta.
5. Aplicar solo fixes revisados.
6. Si existe un literal conocido que debe reescribirse y la sustitucion no puede inferirse con seguridad, preparar un archivo para `--replace-text-file`.
7. Re-ejecutar auditoria hasta `PASS` o hasta dejar identificado el blocker real.
8. Si el repositorio objetivo vive en GitHub y el operador quiere revisar settings remotos, correr tambien `--audit-github-hardening` y distinguir findings reales de settings no endurecidos versus auditoria parcial por falta de token.

## Guardrails

- No usar GUI por defecto.
- No abrir browser automaticamente salvo pedido explicito.
- No hacer push ni rewrite destructivo sin autorizacion explicita.
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

- Resumen PASS/FAIL
- Hallazgos priorizados con evidencia
- Decision de si cada hallazgo amerita fix
- Lista de cambios aplicados
- Referencias a `report.json`, `report.html` y `run.log`
