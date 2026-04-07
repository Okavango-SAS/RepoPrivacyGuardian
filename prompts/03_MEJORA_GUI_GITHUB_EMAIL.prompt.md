# Prompt 03 - Mejora GUI para Git Identity y GitHub Email Privacy

Actua como senior UX + security engineer.
Trabaja EXCLUSIVAMENTE en RepoPrivacyGuardian.

## Objetivo

Mejorar la GUI para que el operador pueda configurar identidad Git de forma segura y guiada, incluyendo privacidad de email en GitHub.

## Requerimientos funcionales obligatorios

1. En la GUI agregar campos claros para:
   - git user.name
   - git user.email (noreply)

2. Agregar acciones en GUI:
   - boton para aplicar config GLOBAL (`git config --global user.name`, `git config --global user.email`)
   - boton para aplicar config LOCAL del repo (`git config --local user.name`, `git config --local user.email`)
   - boton para leer/mostrar config actual efectiva (global/local)

3. Agregar un boton "Open GitHub Email Settings" que abra:
   - https://github.com/settings/emails

4. Mostrar en GUI una ayuda visible (texto o modal) indicando que en GitHub debe activar:
   - "Keep my email addresses private"
   - "Block command line pushes that expose my email"

5. Indicar explicitamente en esa ayuda que desde esa pantalla tambien puede obtener su email noreply.

## Requerimientos de UX

- Etiquetas claras, sin ambiguedad.
- Mensajes de exito/error accionables.
- Confirmacion para acciones que modifiquen config global.
- Evitar friccion: un flujo corto y obvio para quedar bien configurado.

## Requerimientos tecnicos

- Abrir URL con mecanismo estandar de Python (ej. webbrowser.open).
- Manejar fallas de comandos git con mensajes claros.
- Mantener comportamiento seguro por defecto.
- No romper funcionalidades existentes de auditoria/fix.

## Tests obligatorios

Agregar tests para:

- validacion de inputs para name/email
- ejecucion de comandos git (mockeada)
- apertura de URL de GitHub settings (mockeada)
- mensajes y estados de error
- no regresion del flujo principal GUI

## Criterios de aceptacion

- La GUI permite setear user.name y noreply email global/local.
- Existe boton funcional hacia https://github.com/settings/emails.
- La GUI muestra las dos opciones de privacidad exactas a activar.
- Queda claro donde obtener el noreply email.
- Tests nuevos pasan y no rompen cobertura objetivo.
