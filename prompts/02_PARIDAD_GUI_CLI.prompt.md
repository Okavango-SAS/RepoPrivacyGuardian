# Prompt 02 - Paridad GUI vs CLI

Actua como staff engineer de producto y calidad.
Objetivo central: garantizar que GUI y CLI tengan la MISMA funcionalidad y el MISMO flujo operativo.
Trabaja EXCLUSIVAMENTE en RepoPrivacyGuardian.

## Objetivo

Detectar divergencias funcionales entre GUI y CLI, corregirlas, y validar paridad real con pruebas.

## Alcance minimo

Comparar y alinear:

- opciones de auditoria
- opciones de fix/remediacion
- flujo por tabs (`Audit` y `Repair`) y bloqueo visual de `Repair` hasta tener contexto valido de auditoria
- opciones de severidad y reportes
- comportamiento de dry-run
- comportamiento de purge de secretos
- persistencia de artefactos (JSON/LOG/HTML)
- mensajes de salida y manejo de errores

## Reglas

1. No cambiar semantica de seguridad para "hacer pasar" paridad.
2. Si una funcionalidad existe en CLI y falta en GUI (o viceversa), implementar equivalencia.
3. Unificar camino de ejecucion para reducir drift futuro.
4. Agregar tests para prevenir regresion de paridad.

## Tareas obligatorias

1. Construir matriz de paridad actual (CLI vs GUI).
2. Marcar gaps funcionales y de flujo.
3. Implementar correcciones hasta cerrar gaps.
4. Agregar tests automáticos de paridad (argumentos, flags, flujo de salida, errores).
5. Verificar contrato de interaccion GUI: `Audit` como paso inicial y `Repair` bloqueado visualmente hasta auditoria valida.
6. Ejecutar suite y validar cobertura objetivo del repo.
7. Documentar resultado final de la paridad en docs/ENGINEERING_DECISIONS.md o docs/KNOWN_ISSUES.md segun corresponda.

## Entregables

- Matriz antes/despues de paridad.
- Lista de cambios aplicados.
- Evidencia de tests pasando.
- Riesgos o excepciones justificadas (si hubiera).

## Criterios de aceptacion

- No hay diferencias funcionales no justificadas entre GUI y CLI.
- El flujo de corrida y artefactos es equivalente.
- El contrato de tabs GUI (`Audit` -> `Repair`) y el bloqueo visual previo a remediacion quedan explicitamente verificados.
- Tests agregados cubren los escenarios de paridad clave.
- Documentacion actualizada con estado de paridad.
