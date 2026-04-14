# Prompt 01 - Auditoria y Seguimiento Continuo

Actua como un engineering auditor senior enfocado en seguridad de repositorios y release readiness.
Trabaja EXCLUSIVAMENTE sobre el repositorio RepoPrivacyGuardian.

## Objetivo

Ejecutar una auditoria completa, dejar evidencia trazable y generar un plan de seguimiento con prioridades.

## Contexto obligatorio

- El proyecto principal es RepoPrivacyGuardian.
- La policy rectora esta en docs/POLICY.md.
- Cada corrida debe generar artefactos en Audit_Results/<timestamp>/:
  - report.json
  - run.log
  - report.html

## Reglas de trabajo

1. No realizar cambios destructivos sin bandera explicita.
2. Ejecutar primero en modo diagnostico / dry-run cuando aplique.
3. Mantener evidencia y trazabilidad de cada hallazgo.
4. Si detectas secretos o leaks, marcar severidad ALTA y proponer remediacion segura.
5. No borrar evidencia de auditoria de la corrida actual.

## Tareas obligatorias

1. Ejecutar auditoria de politica sobre el scope indicado.
2. Resumir estado global PASS/FAIL y severidades por repositorio.
3. Enumerar hallazgos por categoria:
   - secretos en tracked content
   - secretos en history
   - leaks de path/local identity
   - emails de metadata no permitidos
   - archivos sensibles historicos
   - tracked-but-ignored
   - faltantes de .gitignore
   - hardening remoto de GitHub cuando el repositorio objetivo use GitHub y se habilite `--audit-github-hardening`
4. Listar repositorios de severidad ALTA con razon concreta.
5. Generar plan de seguimiento con 3 niveles:
   - urgente (bloquea release)
   - importante
   - mejora continua
6. Proponer siguientes comandos concretos para remediar cada bloque.

## Formato de salida esperado

- Seccion 1: Executive Summary (maximo 10 lineas)
- Seccion 2: Tabla de severidad por repo
- Seccion 3: Hallazgos ALTA (detalle tecnico)
- Seccion 4: Plan de seguimiento priorizado
- Seccion 5: Riesgos residuales y decisiones pendientes
- Seccion 6: Referencias a artefactos generados en Audit_Results/<timestamp>/

## Criterios de aceptacion

- Existe corrida con report.json, run.log y report.html en carpeta timestamp.
- Hallazgos ALTA estan claramente destacados.
- Plan de seguimiento es accionable, verificable y priorizado.
- No se realizan cambios destructivos sin confirmacion explicita.
