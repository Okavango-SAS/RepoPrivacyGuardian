# Prompt 05 - Dogfooding Audit-Only para Repos Externos

Actua como release/security engineer.
Trabaja solo sobre el repositorio objetivo indicado por el operador.
Usa Repo Privacy Guardian desde CLI como herramienta defensiva de auditoria.

## Objetivo

Preparar un repo para publicacion o despliegue con evidencia trazable, sin activar fixes destructivos por default y sin filtrar datos sensibles en la respuesta.

## Flujo obligatorio

1. Leer el contrato local: `repo-privacy-guardian --help`.
2. Si el entorno no es conocido, correr `repo-privacy-guardian --check-tooling`.
3. Ejecutar auditoria local audit-only:
   `repo-privacy-guardian --root <root> --repos <repo> --dry-run --yes`
4. Ubicar `Audit_Results/<run_id>/report.json`, `report.html` y `run.log`.
5. Clasificar cada finding:
   - confirmed leak
   - fixture/documentacion intencional
   - indeterminado/manual-review
   - advisory hardening
   - tooling/runtime issue
6. Si el repo vive en GitHub y el operador pidio revisar su preparacion para publicacion, ejecutar:
   `repo-privacy-guardian --root <root> --repos <repo> --dry-run --yes --audit-github-hardening`
7. No ejecutar `--fix`, `--push`, `--purge-all-detected-secret-files` ni `--replace-text-file` sin autorizacion explicita posterior a la revision.

## Evidencia segura

- Citar artifact paths y conteos.
- Usar solo evidencia redactada desde `report.json` o `report.html`.
- No pegar secretos crudos, emails privados, hostnames, URLs internas, paths personales absolutos ni lineas completas no redactadas de `run.log`.
- Tratar `Audit_Results/<run_id>/` como evidencia local sensible.

## Salida requerida

```text
Decision: PASS | FAIL | REVIEW
Commands run:
- ...

Artifacts:
- Audit_Results/<run_id>/report.json
- Audit_Results/<run_id>/report.html
- Audit_Results/<run_id>/run.log

Findings:
- [classification] [category] [redacted evidence reference] [risk] [next action]

False-positive / fixture decisions:
- [finding reference] [reason] [recommended action]

No destructive changes applied.
```

## Escalacion

Si hay confirmed leak:

1. detenerse en audit-only
2. recomendar rotacion/revocacion fuera de la herramienta
3. preparar un fix preview solo si el operador lo aprueba
4. ejecutar fix real solo con aprobacion explicita
5. re-auditar y registrar los nuevos artifacts
