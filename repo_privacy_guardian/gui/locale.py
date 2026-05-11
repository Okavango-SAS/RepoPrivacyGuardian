"""GUI locale catalogs, tooltips, and font helpers."""

from __future__ import annotations

import sys

from repo_privacy_guardian import core as _core

GUI_LOCALE_DEFAULT = _core.GUI_LOCALE_DEFAULT
GUI_LOCALE_ES_419 = _core.GUI_LOCALE_ES_419
GITHUB_EMAIL_PRIVACY_HELP = _core.GITHUB_EMAIL_PRIVACY_HELP


def gui_font_candidates(platform_name: str | None = None) -> dict[str, tuple[str, ...]]:
    current_platform = platform_name or sys.platform
    if current_platform.startswith("win"):
        return {
            "ui": ("Segoe UI", "Arial", "TkDefaultFont"),
            "mono": ("Cascadia Mono", "Cascadia Code", "Consolas", "Courier New", "TkFixedFont"),
        }
    if current_platform == "darwin":
        return {
            "ui": ("SF Pro Text", "Helvetica Neue", "Arial", "TkDefaultFont"),
            "mono": ("SF Mono", "Menlo", "Monaco", "Courier", "TkFixedFont"),
        }
    return {
        "ui": ("Inter", "Noto Sans", "DejaVu Sans", "Liberation Sans", "Arial", "TkDefaultFont"),
        "mono": ("JetBrains Mono", "DejaVu Sans Mono", "Liberation Mono", "Courier New", "TkFixedFont"),
    }


GUI_TOOLTIP_TEXT: dict[str, str] = {
    "repositories_root": (
        "Local folder that contains one or more git repositories. Drop repository folders into the list "
        "or use Browse/Refresh to update local targets."
    ),
    "settings_toggle": "Shows or hides setup-only controls. Saved non-secret preferences stay local to this desktop user.",
    "policy_file": "Markdown policy file used by both CLI and GUI to define the publication gate rules.",
    "audit_results_folder": (
        "Base directory for timestamped JSON, HTML, log, and run-state artifacts. Policy keeps outputs under Audit_Results."
    ),
    "optional_json_copy": "Optional second JSON export path for automation. The timestamped report.json is always written.",
    "github_owner": (
        "Opt-in remote audit mode for a GitHub user or organization. The GUI discovers matching repositories, "
        "clones them temporarily, audits them, and keeps Repair locked."
    ),
    "github_repo_filters": (
        "Comma-separated remote repository names to include when GitHub owner/org audit is active. Leave empty "
        "to discover all matching repositories."
    ),
    "github_clone_workers": (
        "Number of concurrent clone workers for GitHub owner/org audit. Higher values can be faster but use more "
        "network, disk, and process capacity."
    ),
    "github_include_forks": (
        "Includes forked repositories in GitHub owner/org discovery. Off by default to avoid auditing inherited "
        "or third-party content unintentionally."
    ),
    "github_fast": (
        "Uses shallow clones in GitHub owner/org audit. Faster for large repos, but history available to the scanner may be limited."
    ),
    "max_findings": (
        "Maximum number of samples retained per check in logs and reports. Lower values keep reports shorter; "
        "higher values aid deep triage."
    ),
    "gui_language": "Language for GUI labels, contextual help, and dialogs. This does not change CLI flags, reports, or behavior.",
    "gui_appearance": "System, Light, or Dark GUI theme. System follows OS theme changes automatically. This is presentation-only and does not change CLI flags, reports, or policy behavior.",
    "save_setup": "Stores only non-secret GUI preferences and collapses setup controls so the main view stays focused on Audit.",
    "advanced_identity": (
        "Shows optional Git identity and GitHub email privacy controls used when Repair rewrites or redacts identity metadata."
    ),
    "noreply_email": "GitHub noreply address used as the safe replacement identity during reviewed repair.",
    "placeholder_email": "Neutral placeholder used when redacting third-party contributor emails during reviewed repair.",
    "owner_name": "Display name to use for rewritten owner commits when identity repair is explicitly authorized.",
    "owner_emails": (
        "Comma-separated private owner emails that can be replaced with the noreply address during reviewed repair."
    ),
    "git_user_name": "Value to read or write for git user.name when applying local/global Git identity settings.",
    "git_user_email": "Noreply-style email to read or write for git user.email in local/global Git config.",
    "apply_global_git_config": (
        "Writes git config --global user.name and user.email for all repositories on this machine after confirmation."
    ),
    "apply_local_git_config": "Writes git user.name and user.email only for the selected local repository.",
    "read_current_git_identity": "Reads effective Git identity without changing local or global Git config.",
    "open_github_email_settings": (
        "Opens GitHub email settings so private-email and push-block protections can be verified manually."
    ),
    "public_only": (
        "Filters local targets to repositories whose GitHub origin is publicly reachable. Useful before public-release checks."
    ),
    "redact_third_party_emails": (
        "During Repair, replaces non-owner contributor emails with the placeholder email. It does nothing during Audit."
    ),
    "low_confidence_blocking": (
        "Turns noisy low-confidence email findings into blocking failures. Leave off unless you want a stricter review gate."
    ),
    "strict_profile": (
        "Applies a CLI-equivalent policy preset. Release is stricter for handoff/publication; audit-only rejects repair and push."
    ),
    "suppression_file": (
        "Versioned JSON file for suppressing only advisory/manual-review categories with owner, reason, and expiration."
    ),
    "dry_run_preview": "Runs Repair in preview mode so planned changes are reported without writing to repositories.",
    "audit_github_hardening": (
        "Adds read-only GitHub settings checks such as branch protection, Actions permissions, secret scanning, and Dependabot."
    ),
    "audit_litellm_incident": "Adds targeted checks for LiteLLM March 2026 supply-chain incident indicators.",
    "open_html_report": "Opens the generated HTML report automatically after a GUI run finishes.",
    "confirm_each_repo_fix": (
        "Prompts before applying Repair to each repository so multi-repo runs can be reviewed one target at a time."
    ),
    "rewrite_personal_paths": (
        "During Repair, rewrites reviewed personal path findings in tracked content and history using replace-text rules."
    ),
    "replace_text_rules": "Optional git-filter-repo replace-text file for literal substitutions the tool cannot infer safely.",
    "force_push": (
        "After a history rewrite, force-pushes changed history to origin. Use only after backups and collaborator coordination."
    ),
    "bypass_remote_owner_guardrail": (
        "Disables the remote-owner safety check before force push. This is intentionally unsafe and requires explicit acceptance."
    ),
    "allowed_remote_owners": "Comma-separated allowlist of remote owners accepted for force-push guardrails.",
    "purge_safe_secret_files": "Purges secret-file candidates classified as safer to remove automatically after review.",
    "purge_risky_secret_files": (
        "Also purges ambiguous/manual-review secret-file candidates. Use only after confirming every candidate."
    ),
    "repair_button": "Runs Repair only after a completed Audit and review window unlock the safety gate.",
    "run_audit": "Runs the publication-gate audit for selected repositories or all visible repositories if confirmed.",
    "stop_after_current_step": (
        "Requests cooperative cancellation. The active repository step finishes cleanly before the run stops."
    ),
    "refresh_repos": "Reloads local repository targets from the current Root folder.",
    "select_all_repos": "Selects every visible local repository target for the next Audit or Repair run.",
    "clear_selection": (
        "Clears local repository selection. If you run Audit with nothing selected, the GUI asks before running all."
    ),
    "clear_log": "Clears only the on-screen log. Existing Audit_Results artifacts are not deleted.",
    "repo_drop_area": (
        "Drag local repository folders here to set the Root and selection automatically. Browse/Refresh remains the fallback."
    ),
    "reports_tab": "Shows the latest local artifact paths and quick-open actions without exposing raw sensitive evidence.",
    "prompts_tab": "Copy vetted agentic IDE prompts that use the CLI-first audit and repair workflow.",
    "open_settings_tab": "Moves advanced parity controls into Settings so Audit stays focused on choosing targets and running the scan.",
    "open_agent_prompts_tab": "Opens the agent prompt library for CLI-first audit, evidence review, and approved repair delegation.",
    "repair_options_toggle": "Shows advanced Repair toggles. Keep them hidden until audited findings have been reviewed.",
    "copy_agent_handoff": (
        "Copies a privacy-safe agent handoff prompt that references the latest redacted artifacts without pasting raw findings."
    ),
    "compare_previous_report": (
        "Compares the latest report.json with the previous local run and copies a count-only regression summary."
    ),
    "copy_prompt": "Copies the full prompt text to the clipboard so it can be pasted into an agentic IDE session.",
    "copy_prompt_command": "Copies the recommended CLI command template for this prompt.",
    "open_prompt_file": "Opens the tracked prompt file for review in the default local application.",
    "workflow_overview": (
        "The desktop companion mirrors the CLI-first workflow: choose targets, audit first, review local artifacts, "
        "copy a safe agent handoff, and repair only after approval."
    ),
    "audit_target_section": (
        "Start here for local work. Choose a repository root, confirm visible targets, then run an audit-only pass "
        "before any repair."
    ),
    "settings_section": (
        "Advanced CLI-parity controls live here so the Audit tab stays focused. These settings map to the same "
        "internal run configuration as CLI flags."
    ),
    "owner_profile_section": (
        "Optional repair defaults for owner identity and GitHub email privacy. They are used only by reviewed "
        "repair actions."
    ),
    "repositories_section": (
        "Visible local repositories for the next run. Select specific targets or leave selection empty and confirm "
        "when asked to run all visible repositories."
    ),
    "execution_log_section": (
        "Live redacted run output for quick monitoring. The durable audit record remains in report.json, "
        "report.html, run.log, and run_state.json."
    ),
    "reports_section": (
        "Use Reports after each run to read the latest artifact paths, decide the next safe action, and copy only "
        "redacted context into an agent session."
    ),
    "latest_artifacts_section": (
        "Shows the latest local evidence bundle from this GUI session. Open artifacts locally instead of pasting "
        "raw findings into chat."
    ),
    "next_action_section": (
        "Decision guidance based on the latest run status. It separates blocking findings, manual review, and "
        "safe agent handoff."
    ),
    "prompts_section": (
        "Vetted prompts for agentic IDEs. They preserve the audit-first workflow and tell the agent to use CLI "
        "artifacts instead of raw sensitive evidence."
    ),
    "agent_workflow_section": (
        "Use the prompt cards in staged order: prepare the environment, audit only, review artifacts, then repair "
        "only after approval."
    ),
    "repair_options_section": (
        "Repair settings are intentionally separated from Audit. Keep write options off until the latest findings "
        "have been reviewed."
    ),
    "repair_flow_section": (
        "Shows the repair gate state and the final Repair action. The button remains locked until a valid audit "
        "has completed and the review window has elapsed."
    ),
}

GUI_TOOLTIP_TEXT_ES_419: dict[str, str] = {
    "repositories_root": (
        "Carpeta local que contiene uno o más repositorios git. Arrastrá carpetas de repositorios a la lista "
        "o usá Buscar/Actualizar para refrescar los objetivos locales."
    ),
    "settings_toggle": "Muestra u oculta controles de configuración inicial. Las preferencias no secretas quedan guardadas sólo para este usuario.",
    "policy_file": "Archivo Markdown de política usado por CLI y GUI para definir las reglas de la barrera de publicación.",
    "audit_results_folder": (
        "Carpeta base para artefactos con timestamp: JSON, HTML, log y estado de corrida. La política mantiene salidas en Audit_Results."
    ),
    "optional_json_copy": "Ruta opcional para una segunda copia JSON destinada a automatización. El report.json con timestamp siempre se escribe.",
    "github_owner": (
        "Modo remoto opt-in para auditar un usuario u organización de GitHub. La GUI descubre repositorios, "
        "los clona temporalmente, los audita y mantiene Reparar bloqueado."
    ),
    "github_repo_filters": (
        "Nombres de repositorios remotos separados por coma para incluir cuando el propietario u organización de GitHub está activo. Dejalo vacío "
        "para descubrir todos los repositorios que coincidan."
    ),
    "github_clone_workers": (
        "Cantidad de clonados concurrentes para auditoría por propietario u organización de GitHub. Valores más altos pueden ser más rápidos, "
        "pero usan más red, disco y procesos."
    ),
    "github_include_forks": (
        "Incluye repositorios derivados en el descubrimiento por propietario u organización de GitHub. Viene apagado para evitar auditar contenido heredado "
        "o de terceros sin querer."
    ),
    "github_fast": (
        "Usa clonados superficiales en auditoría por propietario u organización de GitHub. Es más rápido en repos grandes, pero limita el historial disponible para el escáner."
    ),
    "max_findings": (
        "Cantidad máxima de muestras retenidas por check en logs y reportes. Valores bajos acortan reportes; "
        "valores altos ayudan en triage profundo."
    ),
    "gui_language": "Idioma de etiquetas, ayuda contextual y diálogos de la GUI. No cambia flags, reportes ni contrato CLI.",
    "gui_appearance": "Tema Sistema, Claro u Oscuro. Sistema sigue automáticamente los cambios del sistema operativo. Es sólo presentación y no cambia flags, reportes ni política.",
    "save_setup": "Guarda sólo preferencias no secretas de la GUI y colapsa la configuración para enfocar la vista principal en Auditar.",
    "advanced_identity": (
        "Muestra controles opcionales de identidad Git y privacidad de email GitHub usados cuando Reparar reescribe o redacta metadatos."
    ),
    "noreply_email": "Dirección noreply de GitHub usada como identidad segura de reemplazo durante una reparación revisada.",
    "placeholder_email": "Valor neutral usado al redactar emails de terceros durante una reparación revisada.",
    "owner_name": "Nombre visible a usar en commits del propietario reescritos cuando se autoriza reparación de identidad.",
    "owner_emails": (
        "Emails privados del propietario separados por coma que pueden reemplazarse por la dirección noreply durante una reparación revisada."
    ),
    "git_user_name": "Valor que se lee o escribe en git user.name al aplicar configuración Git local/global.",
    "git_user_email": "Email estilo noreply que se lee o escribe en git user.email en la configuración Git local/global.",
    "apply_global_git_config": (
        "Escribe git config --global user.name y user.email para todos los repositorios de esta máquina luego de confirmar."
    ),
    "apply_local_git_config": "Escribe git user.name y user.email sólo para el repositorio local seleccionado.",
    "read_current_git_identity": "Lee la identidad Git efectiva sin cambiar la configuración local ni global.",
    "open_github_email_settings": (
        "Abre la configuración de email de GitHub para verificar manualmente privacidad de email y bloqueo de pushes con email privado."
    ),
    "public_only": (
        "Filtra objetivos locales a repositorios cuyo origin GitHub sea públicamente accesible. Útil antes de verificaciones de publicación pública."
    ),
    "redact_third_party_emails": (
        "Durante Reparar, reemplaza emails de contribuidores que no son el propietario con el email de reemplazo. No hace nada durante Auditar."
    ),
    "low_confidence_blocking": (
        "Convierte hallazgos ruidosos de email de baja confianza en fallas bloqueantes. Dejalo apagado salvo que quieras una barrera más estricta."
    ),
    "strict_profile": (
        "Aplica un preset de política equivalente al CLI. Release es más estricto para entrega/publicación; solo auditoría rechaza reparación y push."
    ),
    "suppression_file": (
        "JSON versionado para suprimir sólo categorías advisory/de revisión manual con responsable, motivo y vencimiento."
    ),
    "dry_run_preview": "Ejecuta Reparar en modo vista previa para reportar cambios planeados sin escribir en repositorios.",
    "audit_github_hardening": (
        "Agrega verificaciones de solo lectura de configuración GitHub como branch protection, permisos de Actions, secret scanning y Dependabot."
    ),
    "audit_litellm_incident": "Agrega verificaciones focalizadas para indicadores del incidente de cadena de suministro de LiteLLM de marzo de 2026.",
    "open_html_report": "Abre automáticamente el reporte HTML generado cuando termina una corrida desde GUI.",
    "confirm_each_repo_fix": (
        "Pregunta antes de aplicar Reparar en cada repositorio para revisar corridas multi-repo objetivo por objetivo."
    ),
    "rewrite_personal_paths": (
        "Durante Reparar, reescribe hallazgos revisados de rutas personales en contenido versionado e historial usando reglas replace-text."
    ),
    "replace_text_rules": "Archivo replace-text opcional para sustituciones literales que la herramienta no puede inferir de forma segura.",
    "force_push": (
        "Después de reescribir historial, fuerza push a origin. Usalo sólo luego de backups y coordinación con colaboradores."
    ),
    "bypass_remote_owner_guardrail": (
        "Desactiva la verificación de seguridad del propietario remoto antes del push forzado. Es intencionalmente riesgoso y requiere aceptación explícita."
    ),
    "allowed_remote_owners": "Lista permitida separada por coma de propietarios remotos aceptados para el push forzado.",
    "purge_safe_secret_files": "Purga candidatos de archivos secretos clasificados como más seguros de remover automáticamente luego de revisión.",
    "purge_risky_secret_files": (
        "También purga candidatos ambiguos o de revisión manual. Usalo sólo después de confirmar cada candidato."
    ),
    "repair_button": "Ejecuta Reparar sólo después de una Auditoría completa y de que la ventana de revisión libere la barrera de seguridad.",
    "run_audit": "Ejecuta la auditoría de la barrera de publicación para repositorios seleccionados o todos los visibles si lo confirmás.",
    "stop_after_current_step": (
        "Solicita cancelación cooperativa. El paso activo del repositorio termina limpiamente antes de detener la corrida."
    ),
    "refresh_repos": "Recarga objetivos de repositorios locales desde la carpeta raíz actual.",
    "select_all_repos": "Selecciona todos los repositorios locales visibles para la próxima Auditoría o Reparación.",
    "clear_selection": (
        "Limpia la selección local. Si ejecutás Auditar sin selección, la GUI pregunta antes de correr todos."
    ),
    "clear_log": "Limpia sólo el log en pantalla. Los artefactos existentes en Audit_Results no se eliminan.",
    "repo_drop_area": (
        "Arrastrá carpetas de repositorios locales acá para configurar la carpeta raíz y la selección automáticamente. Buscar/Actualizar sigue disponible."
    ),
    "reports_tab": "Muestra rutas de artefactos de la última corrida y acciones rápidas sin exponer evidencia sensible cruda.",
    "prompts_tab": "Copia instrucciones revisadas para IDEs agénticas que usan el flujo prioritario por CLI de auditoría y reparación.",
    "open_settings_tab": "Mueve controles avanzados de paridad a Configuración para que Auditar quede enfocado en objetivos y ejecución.",
    "open_agent_prompts_tab": "Abre la biblioteca de instrucciones para delegar auditoría por CLI, revisión de evidencia y reparación aprobada.",
    "repair_options_toggle": "Muestra opciones avanzadas de Reparar. Mantenelas ocultas hasta revisar los hallazgos auditados.",
    "copy_agent_handoff": (
        "Copia una instrucción segura de traspaso agéntico que referencia los últimos artefactos redactados sin pegar hallazgos crudos."
    ),
    "compare_previous_report": (
        "Compara el último report.json con la corrida local anterior y copia un resumen de regresión sólo con conteos."
    ),
    "copy_prompt": "Copia la instrucción completa al portapapeles para pegarla en una sesión de IDE agéntica.",
    "copy_prompt_command": "Copia el comando CLI recomendado para esta instrucción.",
    "open_prompt_file": "Abre el archivo de instrucción versionado para revisarlo en la aplicación local predeterminada.",
    "workflow_overview": (
        "La GUI acompaña el flujo principal por CLI: elegí objetivos, auditá primero, revisá artefactos locales, "
        "copiá un traspaso seguro para IA y repará sólo después de aprobarlo."
    ),
    "audit_target_section": (
        "Empezá acá para trabajo local. Elegí una carpeta raíz, confirmá los objetivos visibles y ejecutá una "
        "primera auditoría sin reparación."
    ),
    "settings_section": (
        "Los controles avanzados equivalentes al CLI viven acá para que Auditar quede enfocado. Estos ajustes "
        "mapean a la misma configuración interna de corrida que las opciones de línea de comandos."
    ),
    "owner_profile_section": (
        "Valores opcionales de reparación para identidad del propietario y privacidad de email en GitHub. Sólo se "
        "usan en acciones de reparación revisadas."
    ),
    "repositories_section": (
        "Repositorios locales visibles para la próxima corrida. Seleccioná objetivos puntuales o dejá la selección "
        "vacía y confirmá cuando la GUI pregunte si debe correr todos."
    ),
    "execution_log_section": (
        "Salida redactada en vivo para monitoreo rápido. El registro durable queda en report.json, report.html, "
        "run.log y run_state.json."
    ),
    "reports_section": (
        "Usá Reportes después de cada corrida para leer rutas de artefactos, decidir la próxima acción segura y "
        "copiar sólo contexto redactado a una sesión de IA."
    ),
    "latest_artifacts_section": (
        "Muestra el paquete local de evidencia más reciente de esta sesión GUI. Abrí artefactos localmente en vez "
        "de pegar hallazgos crudos en el chat."
    ),
    "next_action_section": (
        "Guía de decisión según el estado de la última corrida. Separa hallazgos bloqueantes, revisión manual y "
        "traspaso seguro a IA."
    ),
    "prompts_section": (
        "Instrucciones revisadas para IDEs agénticas. Conservan el flujo de auditar primero y piden usar "
        "artefactos CLI en vez de evidencia sensible cruda."
    ),
    "agent_workflow_section": (
        "Usá las tarjetas en orden: preparar entorno, auditar sin reparación, revisar artefactos y recién después "
        "reparar si fue aprobado."
    ),
    "repair_options_section": (
        "La configuración de Reparar está separada de Auditar a propósito. Mantené las opciones de escritura "
        "apagadas hasta revisar los hallazgos recientes."
    ),
    "repair_flow_section": (
        "Muestra el estado de la barrera de reparación y la acción final Reparar. El botón queda bloqueado hasta "
        "que una auditoría válida termine y pase la ventana de revisión."
    ),
}

GUI_TOOLTIP_TEXT_BY_LOCALE: dict[str, dict[str, str]] = {
    GUI_LOCALE_DEFAULT: GUI_TOOLTIP_TEXT,
    GUI_LOCALE_ES_419: GUI_TOOLTIP_TEXT_ES_419,
}

GUI_UI_TEXT_BY_LOCALE: dict[str, dict[str, str]] = {
    GUI_LOCALE_DEFAULT: {
        "header_title": "Repo Privacy Guardian",
        "header_subtitle": "Agent-first workflow: audit locally, review redacted evidence, hand off to an IDE agent, then Repair only after approval.",
        "workflow_audit": "1 Audit locally",
        "workflow_review": "2 Review evidence",
        "workflow_agent": "3 Agent handoff",
        "workflow_repair": "4 Gated Repair",
        "workflow_parity": "CLI parity: same backend",
        "tab_audit": "1. Audit",
        "tab_reports": "2. Reports",
        "tab_prompts": "3. Prompts",
        "tab_settings": "4. Settings",
        "tab_repair": "5. Repair",
        "audit_target": "Audit Target",
        "audit_target_body": "Choose local repositories here. Advanced policy, GitHub owner/org, and identity controls live in Settings. Agent prompts stay one click away.",
        "open_settings_tab": "Open Settings",
        "open_agent_prompts_tab": "Agent prompts",
        "last_run": "Last run",
        "last_run_none": "No GUI run has finished in this session yet.",
        "reports_dashboard": "Latest Run Review",
        "reports_dashboard_body": "Review the latest local artifacts, decide the next safe action, then hand off only redacted context.",
        "latest_artifacts": "Latest artifacts",
        "latest_artifacts_none": "Run Audit to create report.json, report.html, run.log, and run_state.json.",
        "next_action": "Next action",
        "next_action_run_audit": "Run Audit first, then review local artifacts here before copying anything into an agent session.",
        "next_action_review_artifacts": "Open report.json and run.log to confirm the run produced repository results before delegating analysis.",
        "next_action_failed": "Review blocking categories in report.html, then copy the agent handoff for classification before enabling Repair.",
        "next_action_manual": "Classify advisory findings with an agent before publication. Repair stays optional and reviewed.",
        "next_action_pass": "No blocking publication findings are present. Keep artifacts for review or copy the handoff for agent sign-off.",
        "next_action_error": "Open run.log and run_state.json, resolve the runtime issue, then run Audit again.",
        "agent_step_evidence": "1. Review redacted evidence",
        "agent_step_copy": "2. Copy agent handoff",
        "agent_step_prompt": "3. Choose a reviewed prompt",
        "open_agent_prompts_from_reports": "Open agent prompts",
        "copy_agent_handoff": "Copy agent handoff",
        "agent_handoff_copied": "Agent handoff copied to clipboard.",
        "agent_handoff_prompt": (
            "Act as a release/security engineer. Review this Repo Privacy Guardian audit using the local artifacts below.\n\n"
            "Run summary:\n"
            "- Run status: {status_label}\n"
            "- Repositories: {repo_count}\n"
            "- Blocking categories: {blocking_count}\n"
            "- Manual-review signals: {manual_count}\n"
            "- Fixture/documentation context: {fixture_count}\n"
            "- Recommended next action: {next_action}\n\n"
            "Classify findings as confirmed leaks, intentional fixtures/examples, indeterminate/manual-review, advisory hardening, "
            "or tooling/runtime issues. Do not paste raw secrets, private emails, internal URLs, hostnames, or personal absolute paths into chat.\n\n"
            "Artifacts:\n"
            "- agent_summary.json: {agent_summary_path}\n"
            "- report.json: {json_path}\n"
            "- report.html: {html_path}\n"
            "- run.log: {log_path}\n"
            "- run_state.json: {state_path}\n\n"
            "Start audit-only. Propose repair steps only after reviewing redacted evidence."
        ),
        "open_html_report_action": "Open HTML report",
        "open_json_report_action": "Open report.json",
        "compare_previous_report_action": "Compare previous run",
        "report_diff_copied": "Run comparison copied to clipboard.",
        "report_diff_no_previous": "No previous report.json was found under Audit_Results.",
        "report_diff_failed": "Run comparison failed: {error}",
        "open_run_log_action": "Open run.log",
        "open_artifacts_folder_action": "Open artifacts folder",
        "prompts_library": "Agent Workflow Prompts",
        "prompts_library_body": "Copy a vetted prompt into Codex, Claude Code, Antigravity, GitHub Copilot, Cursor, or a similar agentic IDE. This is the orchestration layer for analysis, classification, and reviewed repair.",
        "agent_workflow_title": "How to use this tab",
        "agent_workflow_body": "Prepare the environment once, run audit-only first, review local artifacts in Reports, then copy a handoff or repair prompt only after findings are classified.",
        "copy_prompt": "Copy prompt",
        "copy_command": "Copy command",
        "open_prompt": "Open prompt",
        "prompt_command": "Command",
        "prompt_stage_environment_setup": "Preparation",
        "prompt_stage_audit_only": "Audit only",
        "prompt_stage_audit_and_repair": "Reviewed repair",
        "prompt_stage_cli_workflow": "Full delegation",
        "prompt_best_for_environment_setup": "Best before the first local use.",
        "prompt_best_for_audit_only": "Best after choosing the target repo and before any write action.",
        "prompt_best_for_audit_and_repair": "Best after findings were reviewed and approved for cleanup.",
        "prompt_best_for_cli_workflow": "Best when handing the full release/security task to a coding agent.",
        "prompt_copied": "Prompt copied to clipboard.",
        "prompt_command_copied": "Command copied to clipboard.",
        "prompt_open_failed": "Could not open prompt file: {error}",
        "settings_companion_title": "Advanced Settings",
        "settings_companion_body": "These controls preserve CLI parity but stay out of the main audit path.",
        "repair_advanced_toggle_show": "Show advanced Repair options",
        "repair_advanced_toggle_hide": "Hide advanced Repair options",
        "repair_advanced_hint_hidden": "Advanced write options are hidden. Review the audit summary first, then expand only if repair is needed.",
        "repair_advanced_hint_visible": "Advanced Repair options are visible. Confirm the latest audit context before any write action.",
        "recommended_path": "Recommended path",
        "recommended_path_body": "Choose a local root or drop repository folders below. Run Audit first; use Reports and Agent prompts for evidence review and repair orchestration.",
        "repositories_root": "Repositories Root",
        "choose_repositories_root": "Choose the repositories root directory",
        "setup_initial_hint": "Initial setup is open. Save it once, then the main screen stays focused on Audit.",
        "hide_settings": "Hide Settings",
        "open_settings": "Open Settings",
        "setup_settings": "Setup & Settings",
        "settings_status": "Use these controls for policy/output overrides, GitHub owner audits, and advanced identity setup.",
        "gui_language": "GUI Language",
        "gui_appearance": "GUI Theme",
        "policy_file": "Policy File",
        "choose_policy_file": "Choose a policy file",
        "audit_results_folder": "Audit Results Folder",
        "choose_results_folder": "Choose the base results directory",
        "optional_json_copy": "Optional JSON Copy",
        "choose_json_copy": "Choose the extra JSON export path",
        "strict_profile": "Strict profile",
        "suppression_file": "Suppression file",
        "choose_suppression_file": "Choose a suppression JSON file",
        "github_owner": "GitHub Owner / Org",
        "github_owner_placeholder": "optional owner or organization",
        "remote_repo_filters": "Remote repo filters",
        "remote_repo_filters_placeholder": "repo-a, repo-b",
        "clone_workers": "Clone workers",
        "include_forks": "Include forks",
        "fast_shallow_clone": "Fast shallow clone",
        "max_findings": "Max findings per check",
        "settings_persist_note": "These settings persist locally for the GUI. Secret/token values are not stored here.",
        "save_setup": "Save Setup",
        "advanced_identity_hidden": "Advanced identity settings are hidden for the normal audit-only path.",
        "advanced_identity_visible": "Advanced identity settings are visible. Use them only when Repair needs custom metadata.",
        "show_advanced_identity": "Show advanced identity settings",
        "hide_advanced_identity": "Hide advanced identity settings",
        "owner_profile": "Owner Profile (repair defaults)",
        "owner_profile_body": "Used by Repair when rewriting or redacting commit identity metadata.",
        "noreply_email": "Noreply Email",
        "placeholder_email": "Placeholder Email",
        "owner_name": "Owner Name",
        "private_emails_to_replace": "Private emails to replace",
        "optional_git_identity": "Optional: Git Identity & GitHub Email Privacy",
        "git_user_name": "git user.name",
        "git_user_email": "git user.email (noreply)",
        "apply_global_git_config": "Apply Global Git Config",
        "apply_local_git_config": "Apply Local Git Config",
        "read_current_git_identity": "Read Current Git Identity",
        "open_github_email_settings": "Open GitHub Email Settings",
        "github_email_privacy_help": GITHUB_EMAIL_PRIVACY_HELP,
        "identity_help": (
            "Use this only if your local Git identity needs privacy-safe noreply settings. "
            "Use GitHub Email Settings to verify private-email and push-block protections, and to copy your noreply address when needed."
        ),
        "repair_plan_options": "Repair Plan Options",
        "review_output_options": "Review & Output Options",
        "review_output_info": "CLI-equivalent run toggles. They do not rewrite history on their own.",
        "only_audit_public_remotes": "Only audit public remotes",
        "redact_third_party_emails": "Redact third-party emails during repair",
        "low_confidence_blocking": "Treat low-confidence emails as blocking",
        "dry_run_preview": "Dry run / preview repair",
        "audit_github_hardening": "Audit GitHub release hardening",
        "audit_litellm_incident": "Audit LiteLLM incident (Mar-2026)",
        "open_html_report": "Open HTML report automatically",
        "confirm_each_repo_fix": "Confirm each repository during repair",
        "repair_write_actions": "Repair Write Actions",
        "repair_write_info": "These options are only applied when you click Repair.",
        "repair_write_body": "Only applied when you click Repair. Review the latest audit summary before enabling them.",
        "rewrite_personal_paths": "Rewrite personal paths in history",
        "rewrite_personal_paths_body": "Uses reviewed replace-text rules during repair to rewrite detected personal paths.",
        "replace_text_rules": "Additional Replace-Text Rules",
        "choose_replace_text_file": "Choose an explicit replace-text file",
        "replace_text_rules_body": "Optional operator-reviewed literal replacements for cleanup the tool cannot infer safely.",
        "force_push": "Force-push rewritten history",
        "bypass_remote_owner_guardrail": "Bypass remote-owner guardrail",
        "allowed_remote_owners": "Allowed remote owners",
        "allowed_remote_owners_body": "Use a comma-separated allowlist. Leave bypass off to keep owner verification active.",
        "purge_safe_secret_files": "Purge safe secret-file candidates",
        "purge_risky_secret_files": "Purge risky manual-review candidates too",
        "purge_body": "Safe mode skips ambiguous files. Risky mode also includes candidates that still need manual judgment.",
        "repair_flow": "Repair Flow",
        "audit_required": "Audit required",
        "audit_again_required": "Audit again required",
        "latest_audit_summary": "Latest audit summary",
        "no_audit_results": "No audit results in this session yet. Run Audit first, then review the summary before applying write actions.",
        "repair_stays_disabled": "Repair stays disabled until Audit finishes and the review window completes.",
        "repair_review_pending_note": "Review the audit summary first. Repair unlocks when the review window completes.",
        "repair_ready_note": "Repair is available for reviewed cleanup actions. Keep destructive options off unless explicitly approved.",
        "repair_tab_locked": "Repair tab locked",
        "before_repair": "Before Repair, do this:",
        "repair_lock_step_1": "1. Run Audit and confirm the selected repositories are the ones you want to review.",
        "repair_lock_step_2": "2. Read the log and findings summary before enabling any write actions.",
        "repair_lock_step_3": "3. Come back here only when you are ready to confirm a repair plan.",
        "go_to_audit": "Go to Audit",
        "repositories": "Repositories",
        "run_audit": "Run Audit",
        "audit_unavailable": "Audit unavailable",
        "stop_after_current_step": "Stop After Current Step",
        "stopping_after_current_step": "Stopping after current step...",
        "refresh": "Refresh",
        "repo_summary_default": "Select repositories, drop repository folders, or leave empty to audit every repository shown under Root.",
        "repo_drop_hint": "Drag repository folders here, or use Browse / Refresh.",
        "repo_drop_ready": "Drag repository folders here to set the audit target, or use Browse / Refresh.",
        "repo_drop_unavailable": "Drag-and-drop is unavailable in this Tk runtime. Use Browse / Refresh. ({error})",
        "repo_drop_registration_failed": "Drag-and-drop registration failed. Use Browse / Refresh. ({error})",
        "repo_targets_unavailable": "Repository targets unavailable",
        "choose_valid_root": "Choose a valid Root folder to load one or more git repositories.",
        "run_audit_available_hint": "Run Audit becomes available once at least one repository target is visible in this list.",
        "select_all": "Select All",
        "clear_selection": "Clear Selection",
        "clear_log": "Clear Log",
        "execution_log": "Execution Log",
        "execution_log_empty": (
            "Ready for audit.\n"
            "Run Audit to stream progress here.\n"
            "Reports keeps artifacts and the agent handoff."
        ),
        "browse": "Browse…",
        "save_as": "Save As…",
        "setup_hint_open": "Setup is open. Save it once, then the main screen stays focused on Audit.",
        "setup_hint_remote": "Settings hidden. GitHub owner/org remote audit is active for {github_owner} (audit-only; local list ignored). Open Settings to edit.",
        "setup_hint_hidden": "Setup is saved and hidden. Open Settings for policy, output, GitHub, or identity controls.",
        "all_matching_repositories": "all matching repositories",
        "named_remote_repo_singular": "{count} named remote repository",
        "named_remote_repo_plural": "{count} named remote repositories",
        "github_remote_state": (
            "Audit will discover {filter_text} for {github_owner}, clone them into a temporary private directory, "
            "and remove the clones when the run finishes. Remote mode is audit-only, so Repair stays unavailable for these targets."
        ),
        "repo_empty_invalid_root_title": "Root folder not found",
        "repo_empty_invalid_root_hint": "Pick a valid directory, then refresh the repository list.",
        "repo_empty_choose_root_action": "Choose Root",
        "repo_empty_no_repos_title": "No repositories found",
        "repo_empty_no_repos_hint": "Clone a repository here or point Root at a folder that already contains git repositories.",
        "repo_empty_github_remote_title": "GitHub owner/org audit active",
        "repo_empty_github_remote_hint": "Local repository selection is paused. Open Settings to edit or clear the GitHub owner/org.",
        "repo_summary_remote": (
            "GitHub owner/org audit is active for {github_owner}. The local repository list is ignored; Audit will discover "
            "{filter_text} through GitHub and keep Repair locked because remote mode is audit-only."
        ),
        "repo_summary_invalid_root": "Root folder not found. Choose a valid directory before running Audit.",
        "repo_summary_no_repos": "No git repositories detected under Root yet. Choose another folder or refresh after cloning.",
        "repo_word_singular": "repository",
        "repo_word_plural": "repositories",
        "no_repos_selected": "No repositories selected.",
        "selected_count": "{count} selected.",
        "current_root_available": " Current Root is available in the list.",
        "current_root_label": "Current Root",
        "repo_summary_targets": (
            "Step 2: {total} {repo_word} shown under Root. {selected_text} "
            "Leave the selection empty to audit every repository shown.{root_hint}"
        ),
        "lock_repair_default": "Repair (run audit first)",
        "lock_repair_run_again": "Repair (run audit again)",
        "lock_repair_cancelled": "Repair (audit cancelled)",
        "lock_repair_failed": "Repair (audit failed)",
        "lock_repair_remote": "Repair (remote audit is audit-only)",
        "lock_repair_in_progress": "Repair (audit in progress)",
        "lock_repair_no_results": "Repair (no audited results yet)",
        "lock_repair_message": "{reason}. Run Audit again before applying more write actions.",
        "repair_wait": "Repair (wait {seconds}s)",
        "repair": "Repair",
        "review_window": "Review window",
        "repair_ready": "Repair ready",
        "optional_cleanup": "Optional cleanup",
        "repair_unlocks_after_review": " Repair unlocks after the review window completes.",
        "repair_now_available": " Repair is now available if you still want to apply reviewed cleanup actions.",
        "repair_unlocks_in": " Repair unlocks in {seconds}s.",
        "repair_lock_default_reason": "Repair stays locked until a valid audit has completed.",
        "repair_lock_message": "{reason}\n\nRun Audit, review the results, and return here only when the repair plan is ready to confirm.",
        "last_audit_failed": "Last audit: {label}. {failed} FAIL / {passed} PASS.{detail_text} Review the findings and confirm every write action before Repair.",
        "last_audit_passed_manual": "Last audit: {label}. All selected repositories passed.{detail_text} Classify advisory findings before publication; Repair is optional and should only apply reviewed cleanup actions.",
        "last_audit_passed": "Last audit: {label}. All selected repositories passed.{detail_text} Repair is optional; use it only if you still want to apply reviewed cleanup actions.",
        "blocking_category_singular": "{count} blocking category",
        "blocking_category_plural": "{count} blocking categories",
        "manual_signal_singular": "{count} manual-review signal",
        "manual_signal_plural": "{count} manual-review signals",
        "fixture_match_singular": "{count} fixture/documentation match kept non-blocking",
        "fixture_match_plural": "{count} fixture/documentation matches kept non-blocking",
        "repair_plan_intro": "Repair will run with the following plan:",
        "active_options": "Active options:",
        "yes": "YES",
        "no": "NO",
        "auto_owner": "(auto from noreply if available)",
        "plan_rewrite_paths": "- Rewrite personal paths: {value}",
        "plan_replace_text": "- Explicit replace-text file: {value}",
        "plan_purge_safe": "- Purge SAFE: {value}",
        "plan_purge_risky": "- Purge RISKY: {value}",
        "plan_force_push": "- Force push remote: {value}",
        "plan_open_report": "- Open HTML report automatically: {value}",
        "plan_confirm_each_repo": "- Confirm each repo fix: {value}",
        "plan_allow_bypass": "- Allow non-owner push bypass: {value}",
        "plan_allowed_owners": "- Allowed push owner(s): {value}",
        "repair_baseline_changes": "Repair baseline changes:",
        "baseline_gitignore": "- May add missing .gitignore patterns",
        "baseline_untrack": "- May run git rm --cached on tracked-but-ignored files",
        "baseline_rewrite": "- May rewrite history with git-filter-repo depending on the selected options",
        "risky_warning_1": "WARNING: you selected RISKY options (purge all, force push, or owner-guardrail bypass).",
        "risky_warning_2": "This can remove historical content irreversibly and/or bypass remote-owner protections.",
        "audited_findings_summary": "Explicit summary of audited findings:",
        "repo_status_line": "- {name} [{status}]",
        "blocking_categories_line": "  * Blocking categories: {count}",
        "manual_review_signals_line": "  * Manual-review signals: {count}",
        "fixture_context_line": "  * Fixture/documentation matches kept non-blocking: {count}",
        "planned_untrack_line": "  * Planned untrack (tracked-but-ignored): {count}",
        "planned_path_rewrite_line": "  * Planned personal-path rewrite: {count} findings",
        "personal_paths_disabled": "  * Personal paths: rewrite disabled",
        "planned_purge_risky_line": "  * Planned Purge RISKY: {count} candidates",
        "planned_purge_safe_line": "  * Planned Purge SAFE: {count} candidates",
        "more_items": "    - ... and {count} more",
        "secret_purge_disabled": "  * Secret-file purge: disabled",
        "continue_question": "Continue?",
        "rerun_if_changed": "(If you changed the repo selection or options, run Audit again first.)",
        "dialog_repair_locked_title": "Repair Locked",
        "dialog_repair_locked_review": "Repair becomes available only after a completed audit and a 10-second review window.",
        "dialog_repair_locked_no_results": "There are no audit results in this session yet. Run Audit first.",
        "dialog_new_audit_required_title": "New Audit Required",
        "dialog_new_audit_required": "The current repo selection does not match the last audit. Run Audit again before Repair.",
        "dialog_confirm_repair_title": "Confirm Repair Plan",
        "dialog_risk_title": "Risk Acceptance Required",
        "dialog_risk_message": "You selected RISKY options (purge all, force push, or owner-guardrail bypass).\nConfirm that you accept continuing AT YOUR OWN RISK.",
        "dialog_invalid_git_identity": "Invalid Git identity",
        "dialog_confirm_global_git_config": "Confirm Global Git Config",
        "dialog_confirm_global_git_config_message": "This updates git config --global for all repositories on this machine. Continue?",
        "dialog_global_git_config": "Global Git Config",
        "dialog_local_git_config": "Local Git Config",
        "dialog_read_git_identity": "Read Git Identity",
        "dialog_read_git_identity_select_one": "Select zero or one repository to inspect local/effective git identity.",
        "dialog_not_git_repo": "Not a git repository: {candidate}",
        "dialog_current_git_identity": "Current Git Identity",
        "dialog_github_email_settings": "GitHub Email Settings",
        "dialog_run_in_progress": "Run In Progress",
        "dialog_run_in_progress_message": "There is already an execution in progress. Wait until it finishes.",
        "dialog_remote_audit_only": "Remote Audit Is Audit-Only",
        "dialog_remote_audit_only_message": "GitHub owner/org remote audit cannot be combined with Repair. Clear GitHub Owner / Org before repairing local repositories.",
        "dialog_run_all_title": "Run all repositories",
        "dialog_run_all_message": "No repositories selected. Run {action_name} for all repositories under Root?",
        "dialog_invalid_max_matches": "Invalid Max Matches",
        "dialog_invalid_max_matches_message": "Max matches must be a positive integer.",
        "dialog_invalid_github_jobs": "Invalid GitHub Jobs",
        "dialog_invalid_github_jobs_message": "GitHub clone workers must be a positive integer.",
        "action_repair": "repair",
        "action_audit": "audit",
        "confirm_repo_repair_title": "Confirm Repair for This Repository",
        "confirm_repo_repair_message": "Repository {index}/{total}: {repo_name}\n\nApply Repair to this repository?\nYou can answer No to skip only this repository.",
        "install_github_tooling_title": "Install GitHub Tooling",
        "install_github_tooling_intro": "GitHub hardening checks work best with GitHub CLI (`gh`) and, on Windows, a healthy App Installer / winget setup.",
        "install_github_tooling_confirm": "Install or repair that tooling now?",
        "github_auth_needed_title": "GitHub Authentication Still Needed",
        "github_auth_needed_message": "GitHub CLI is installed, but token-gated hardening checks still need authentication.\n\nRun `gh auth login`, or set REPO_PRIVACY_GUARDIAN_GITHUB_TOKEN, GITHUB_TOKEN, or GH_TOKEN.",
    },
    GUI_LOCALE_ES_419: {
        "header_title": "Repo Privacy Guardian",
        "header_subtitle": "Flujo prioritario para agentes: auditá localmente, revisá evidencia redactada, pasala a una IDE agéntica y Repará sólo con aprobación.",
        "workflow_audit": "1 Auditar local",
        "workflow_review": "2 Revisar evidencia",
        "workflow_agent": "3 Traspaso IA",
        "workflow_repair": "4 Reparar con control",
        "workflow_parity": "Paridad CLI: mismo motor",
        "tab_audit": "1. Auditar",
        "tab_reports": "2. Reportes",
        "tab_prompts": "3. Instrucciones",
        "tab_settings": "4. Configuración",
        "tab_repair": "5. Reparar",
        "audit_target": "Objetivo de auditoría",
        "audit_target_body": "Elegí repositorios locales acá. Los controles avanzados de política, propietario u organización de GitHub e identidad viven en Configuración. Las instrucciones agénticas quedan a un clic.",
        "open_settings_tab": "Abrir configuración",
        "open_agent_prompts_tab": "Instrucciones IA",
        "last_run": "Última corrida",
        "last_run_none": "Todavía no terminó ninguna corrida GUI en esta sesión.",
        "reports_dashboard": "Revisión de última corrida",
        "reports_dashboard_body": "Revisá los artefactos locales recientes, decidí la próxima acción segura y pasá sólo contexto redactado.",
        "latest_artifacts": "Últimos artefactos",
        "latest_artifacts_none": "Ejecutá Auditar para crear report.json, report.html, run.log y run_state.json.",
        "next_action": "Próxima acción",
        "next_action_run_audit": "Ejecutá Auditar primero. Después revisá acá los artefactos locales antes de pasar contexto a una sesión agéntica.",
        "next_action_review_artifacts": "Abrí report.json y run.log para confirmar que la corrida produjo resultados antes de delegar análisis.",
        "next_action_failed": "Revisá categorías bloqueantes en report.html. Después copiá el contexto agéntico para clasificar evidencia antes de Reparar.",
        "next_action_manual": "Clasificá señales consultivas con un agente antes de publicar. Reparar queda opcional y revisado.",
        "next_action_pass": "No hay bloqueos de publicación en los resultados. Conservá artefactos o copiá el contexto para una revisión agéntica final.",
        "next_action_error": "Abrí run.log y run_state.json, resolvé el problema de ejecución y repetí Auditar.",
        "agent_step_evidence": "1. Revisar evidencia redactada",
        "agent_step_copy": "2. Copiar contexto agéntico",
        "agent_step_prompt": "3. Elegir instrucción revisada",
        "open_agent_prompts_from_reports": "Abrir instrucciones",
        "copy_agent_handoff": "Copiar contexto agéntico",
        "agent_handoff_copied": "Contexto agéntico copiado al portapapeles.",
        "agent_handoff_prompt": (
            "Actuá como ingeniero/a de publicación y seguridad. Revisá esta auditoría de Repo Privacy Guardian usando los artefactos locales de abajo.\n\n"
            "Resumen de corrida:\n"
            "- Estado de corrida: {status_label}\n"
            "- Repositorios: {repo_count}\n"
            "- Categorías bloqueantes: {blocking_count}\n"
            "- Señales para revisión manual: {manual_count}\n"
            "- Contexto de datos de prueba/documentación: {fixture_count}\n"
            "- Próxima acción recomendada: {next_action}\n\n"
            "Clasificá hallazgos como filtraciones confirmadas, datos de prueba/ejemplos intencionales, indeterminados para revisión manual, endurecimiento consultivo "
            "o problemas de herramientas/tiempo de ejecución. No pegues secretos crudos, emails privados, URLs internas, nombres de host ni rutas absolutas personales en el chat.\n\n"
            "Artefactos:\n"
            "- agent_summary.json: {agent_summary_path}\n"
            "- report.json: {json_path}\n"
            "- report.html: {html_path}\n"
            "- run.log: {log_path}\n"
            "- run_state.json: {state_path}\n\n"
            "Empezá en modo solo auditoría. Proponé reparaciones sólo después de revisar evidencia redactada."
        ),
        "open_html_report_action": "Abrir reporte HTML",
        "open_json_report_action": "Abrir report.json",
        "compare_previous_report_action": "Comparar corrida anterior",
        "report_diff_copied": "Comparación de corridas copiada al portapapeles.",
        "report_diff_no_previous": "No se encontró un report.json anterior en Audit_Results.",
        "report_diff_failed": "Falló la comparación de corridas: {error}",
        "open_run_log_action": "Abrir run.log",
        "open_artifacts_folder_action": "Abrir carpeta de artefactos",
        "prompts_library": "Instrucciones para flujo agéntico",
        "prompts_library_body": "Copiá una instrucción revisada en Codex, Claude Code, Antigravity, GitHub Copilot, Cursor o una IDE agéntica similar. Esta es la capa de orquestación para análisis, clasificación y reparación revisada.",
        "agent_workflow_title": "Cómo usar esta pestaña",
        "agent_workflow_body": "Prepará el entorno una vez, ejecutá primero en modo solo auditoría, revisá artefactos locales en Reportes y recién después copiá un traspaso o una instrucción de reparación cuando los hallazgos estén clasificados.",
        "copy_prompt": "Copiar instrucción",
        "copy_command": "Copiar comando",
        "open_prompt": "Abrir instrucción",
        "prompt_command": "Comando",
        "prompt_stage_environment_setup": "Preparación",
        "prompt_stage_audit_only": "Solo auditoría",
        "prompt_stage_audit_and_repair": "Reparación revisada",
        "prompt_stage_cli_workflow": "Delegación completa",
        "prompt_best_for_environment_setup": "Para antes del primer uso local.",
        "prompt_best_for_audit_only": "Para después de elegir el repositorio objetivo y antes de cualquier escritura.",
        "prompt_best_for_audit_and_repair": "Para después de revisar hallazgos y aprobar limpieza.",
        "prompt_best_for_cli_workflow": "Para pasar la tarea completa de publicación y seguridad a un agente de código.",
        "prompt_copied": "Instrucción copiada al portapapeles.",
        "prompt_command_copied": "Comando copiado al portapapeles.",
        "prompt_open_failed": "No se pudo abrir el archivo de instrucción: {error}",
        "settings_companion_title": "Configuración avanzada",
        "settings_companion_body": "Estos controles preservan paridad CLI pero quedan fuera del camino principal de auditoría.",
        "repair_advanced_toggle_show": "Mostrar opciones avanzadas de Reparar",
        "repair_advanced_toggle_hide": "Ocultar opciones avanzadas de Reparar",
        "repair_advanced_hint_hidden": "Las opciones avanzadas de escritura están ocultas. Revisá el resumen de auditoría y expandí sólo si hace falta reparar.",
        "repair_advanced_hint_visible": "Las opciones avanzadas de Reparar están visibles. Confirmá el contexto de la última auditoría antes de cualquier acción de escritura.",
        "recommended_path": "Camino recomendado",
        "recommended_path_body": "Elegí una carpeta raíz local o arrastrá repositorios abajo. Ejecutá Auditar primero; usá Reportes e Instrucciones IA para revisar evidencia y orquestar reparaciones.",
        "repositories_root": "Carpeta raíz de repositorios",
        "choose_repositories_root": "Elegir la carpeta raíz de repositorios",
        "setup_initial_hint": "La configuración inicial está abierta. Guardala una vez y la pantalla principal queda enfocada en Auditar.",
        "hide_settings": "Ocultar configuración",
        "open_settings": "Abrir configuración",
        "setup_settings": "Preparación y configuración",
        "settings_status": "Usá estos controles para política/salida, auditorías por propietario u organización de GitHub e identidad avanzada.",
        "gui_language": "Idioma de la GUI",
        "gui_appearance": "Tema de la GUI",
        "policy_file": "Archivo de política",
        "choose_policy_file": "Elegir un archivo de política",
        "audit_results_folder": "Carpeta de resultados",
        "choose_results_folder": "Elegir la carpeta base de resultados",
        "optional_json_copy": "Copia JSON opcional",
        "choose_json_copy": "Elegir la ruta extra de export JSON",
        "strict_profile": "Perfil estricto",
        "suppression_file": "Archivo de supresiones",
        "choose_suppression_file": "Elegir archivo JSON de supresiones",
        "github_owner": "Propietario u organización de GitHub",
        "github_owner_placeholder": "propietario u organización opcional",
        "remote_repo_filters": "Filtros de repos remotos",
        "remote_repo_filters_placeholder": "repo-a, repo-b",
        "clone_workers": "Procesos de clonado",
        "include_forks": "Incluir forks (bifurcaciones)",
        "fast_shallow_clone": "Clonado superficial rápido",
        "max_findings": "Máx. hallazgos por check",
        "settings_persist_note": "Estas preferencias quedan guardadas localmente para la GUI. No se guardan secretos ni tokens.",
        "save_setup": "Guardar configuración",
        "advanced_identity_hidden": "La identidad avanzada está oculta para el flujo normal de solo auditoría.",
        "advanced_identity_visible": "La identidad avanzada está visible. Usala sólo si Reparar necesita metadatos personalizados.",
        "show_advanced_identity": "Mostrar identidad avanzada",
        "hide_advanced_identity": "Ocultar identidad avanzada",
        "owner_profile": "Perfil del propietario (valores por defecto de reparación)",
        "owner_profile_body": "Lo usa Reparar al reescribir o redactar metadatos de identidad de commits.",
        "noreply_email": "Email noreply",
        "placeholder_email": "Email de reemplazo",
        "owner_name": "Nombre del propietario",
        "private_emails_to_replace": "Emails privados a reemplazar",
        "optional_git_identity": "Opcional: identidad Git y privacidad de email GitHub",
        "git_user_name": "git user.name",
        "git_user_email": "git user.email (noreply)",
        "apply_global_git_config": "Aplicar configuración Git global",
        "apply_local_git_config": "Aplicar configuración Git local",
        "read_current_git_identity": "Leer identidad Git actual",
        "open_github_email_settings": "Abrir configuración de email de GitHub",
        "github_email_privacy_help": (
            "Usá la configuración de email de GitHub para verificar privacidad de email, bloqueo de pushes con email privado "
            "y copiar tu dirección noreply cuando haga falta."
        ),
        "identity_help": (
            "Usá esto sólo si tu identidad Git local necesita configuración noreply segura. "
            "Usá la configuración de email de GitHub para verificar privacidad de email, bloqueo de pushes con email privado y copiar tu dirección noreply cuando haga falta."
        ),
        "repair_plan_options": "Opciones del plan de reparación",
        "review_output_options": "Opciones de revisión y salida",
        "review_output_info": "Opciones equivalentes al CLI. No reescriben historial por sí solas.",
        "only_audit_public_remotes": "Auditar sólo remotos públicos",
        "redact_third_party_emails": "Redactar emails de terceros al reparar",
        "low_confidence_blocking": "Tratar emails de baja confianza como bloqueantes",
        "dry_run_preview": "Simulación / vista previa de reparación",
        "audit_github_hardening": "Auditar endurecimiento de publicación en GitHub",
        "audit_litellm_incident": "Auditar incidente LiteLLM (mar-2026)",
        "open_html_report": "Abrir reporte HTML automáticamente",
        "confirm_each_repo_fix": "Confirmar cada repositorio al reparar",
        "repair_write_actions": "Acciones de escritura de Reparar",
        "repair_write_info": "Estas opciones sólo se aplican cuando hacés clic en Reparar.",
        "repair_write_body": "Sólo se aplican cuando hacés clic en Reparar. Revisá el último resumen de auditoría antes de activarlas.",
        "rewrite_personal_paths": "Reescribir rutas personales en historial",
        "rewrite_personal_paths_body": "Usa reglas replace-text revisadas durante Reparar para reescribir rutas personales detectadas.",
        "replace_text_rules": "Reglas replace-text adicionales",
        "choose_replace_text_file": "Elegir un archivo replace-text explícito",
        "replace_text_rules_body": "Reemplazos literales revisados por operador para limpieza que la herramienta no puede inferir con seguridad.",
        "force_push": "Push forzado del historial reescrito",
        "bypass_remote_owner_guardrail": "Omitir protección de propietario remoto",
        "allowed_remote_owners": "Propietarios remotos permitidos",
        "allowed_remote_owners_body": "Usá una lista permitida separada por coma. Dejá esta omisión apagada para mantener la verificación de propietario.",
        "purge_safe_secret_files": "Purgar candidatos seguros de archivos secretos",
        "purge_risky_secret_files": "Purgar también candidatos riesgosos/de revisión manual",
        "purge_body": "El modo seguro omite archivos ambiguos. El modo riesgoso también incluye candidatos que requieren juicio manual.",
        "repair_flow": "Flujo de reparación",
        "audit_required": "Auditoría requerida",
        "audit_again_required": "Nueva auditoría requerida",
        "latest_audit_summary": "Último resumen de auditoría",
        "no_audit_results": "Todavía no hay resultados de auditoría en esta sesión. Ejecutá Auditar primero y revisá el resumen antes de aplicar acciones de escritura.",
        "repair_stays_disabled": "Reparar queda deshabilitado hasta que Auditar termine y se complete la ventana de revisión.",
        "repair_review_pending_note": "Revisá primero el resumen de auditoría. Reparar se habilita cuando termina la ventana de revisión.",
        "repair_ready_note": "Reparar está disponible para limpiezas revisadas. Mantené apagadas las opciones destructivas salvo aprobación explícita.",
        "repair_tab_locked": "Pestaña Reparar bloqueada",
        "before_repair": "Antes de Reparar, hacé esto:",
        "repair_lock_step_1": "1. Ejecutá Auditar y confirmá que seleccionaste los repositorios correctos.",
        "repair_lock_step_2": "2. Leé el log y el resumen de hallazgos antes de activar acciones de escritura.",
        "repair_lock_step_3": "3. Volvé acá sólo cuando estés listo para confirmar un plan de reparación.",
        "go_to_audit": "Ir a Auditar",
        "repositories": "Repositorios",
        "run_audit": "Ejecutar Auditar",
        "audit_unavailable": "Auditoría no disponible",
        "stop_after_current_step": "Detener luego del paso actual",
        "stopping_after_current_step": "Deteniendo luego del paso actual...",
        "refresh": "Actualizar",
        "repo_summary_default": "Seleccioná repositorios, arrastrá carpetas o dejá vacío para auditar todo lo visible bajo la carpeta raíz.",
        "repo_drop_hint": "Arrastrá carpetas de repositorios acá, o usá Buscar / Actualizar.",
        "repo_drop_ready": "Arrastrá carpetas de repositorios acá para configurar el objetivo de auditoría, o usá Buscar / Actualizar.",
        "repo_drop_unavailable": "Arrastrar y soltar no está disponible en este entorno Tk. Usá Buscar / Actualizar. ({error})",
        "repo_drop_registration_failed": "Falló el registro de arrastrar y soltar. Usá Buscar / Actualizar. ({error})",
        "repo_targets_unavailable": "Objetivos de repositorio no disponibles",
        "choose_valid_root": "Elegí una carpeta raíz válida para cargar uno o más repositorios git.",
        "run_audit_available_hint": "Ejecutar Auditar queda disponible cuando hay al menos un repositorio visible en esta lista.",
        "select_all": "Seleccionar todo",
        "clear_selection": "Limpiar selección",
        "clear_log": "Limpiar log",
        "execution_log": "Log de ejecución",
        "execution_log_empty": (
            "Listo para auditar.\n"
            "Ejecutá Auditar para ver el progreso acá.\n"
            "Reportes conserva artefactos y el traspaso agéntico."
        ),
        "browse": "Buscar…",
        "save_as": "Guardar como…",
        "setup_hint_open": "Configuración abierta. Guardala una vez y la pantalla principal queda enfocada en Auditar.",
        "setup_hint_remote": "Configuración oculta. Auditoría remota por propietario u organización de GitHub activa para {github_owner} (solo auditoría; se ignora la lista local). Abrí Configuración para editar.",
        "setup_hint_hidden": "Configuración guardada y oculta. Abrí Configuración para política, salida, GitHub o identidad.",
        "all_matching_repositories": "todos los repositorios que coincidan",
        "named_remote_repo_singular": "{count} repositorio remoto nombrado",
        "named_remote_repo_plural": "{count} repositorios remotos nombrados",
        "github_remote_state": (
            "Auditar va a descubrir {filter_text} para {github_owner}, clonarlos en una carpeta privada temporal "
            "y eliminar los clones al finalizar. El modo remoto es solo auditoría, así que Reparar queda no disponible para esos objetivos."
        ),
        "repo_empty_invalid_root_title": "Carpeta raíz no encontrada",
        "repo_empty_invalid_root_hint": "Elegí un directorio válido y después actualizá la lista de repositorios.",
        "repo_empty_choose_root_action": "Elegir carpeta",
        "repo_empty_no_repos_title": "No se encontraron repositorios",
        "repo_empty_no_repos_hint": "Cloná un repositorio acá o apuntá la carpeta raíz a una carpeta que ya contenga repositorios git.",
        "repo_empty_github_remote_title": "Auditoría por propietario u organización de GitHub activa",
        "repo_empty_github_remote_hint": "La selección local está pausada. Abrí Configuración para editar o limpiar el propietario u organización de GitHub.",
        "repo_summary_remote": (
            "La auditoría por propietario u organización de GitHub está activa para {github_owner}. La lista local se ignora; Auditar va a descubrir "
            "{filter_text} vía GitHub y mantener Reparar bloqueado porque el modo remoto es solo auditoría."
        ),
        "repo_summary_invalid_root": "Carpeta raíz no encontrada. Elegí un directorio válido antes de ejecutar Auditar.",
        "repo_summary_no_repos": "No se detectaron repositorios git bajo la carpeta raíz. Elegí otra carpeta o actualizá después de clonar.",
        "repo_word_singular": "repositorio",
        "repo_word_plural": "repositorios",
        "no_repos_selected": "No hay repositorios seleccionados.",
        "selected_count": "{count} seleccionados.",
        "current_root_available": " La carpeta raíz actual está disponible en la lista.",
        "current_root_label": "Carpeta raíz actual",
        "repo_summary_targets": (
            "Paso 2: {total} {repo_word} visibles bajo la carpeta raíz. {selected_text} "
            "Dejá la selección vacía para auditar todos los repositorios visibles.{root_hint}"
        ),
        "lock_repair_default": "Reparar (ejecutá auditoría primero)",
        "lock_repair_run_again": "Reparar (volvé a auditar)",
        "lock_repair_cancelled": "Reparar (auditoría cancelada)",
        "lock_repair_failed": "Reparar (auditoría fallida)",
        "lock_repair_remote": "Reparar (auditoría remota es solo auditoría)",
        "lock_repair_in_progress": "Reparar (auditoría en curso)",
        "lock_repair_no_results": "Reparar (sin resultados auditados)",
        "lock_repair_message": "{reason}. Ejecutá Auditar nuevamente antes de aplicar más acciones de escritura.",
        "repair_wait": "Reparar (esperá {seconds}s)",
        "repair": "Reparar",
        "review_window": "Ventana de revisión",
        "repair_ready": "Reparación lista",
        "optional_cleanup": "Limpieza opcional",
        "repair_unlocks_after_review": " Reparar se desbloquea cuando termina la ventana de revisión.",
        "repair_now_available": " Reparar ya está disponible si todavía querés aplicar acciones de limpieza revisadas.",
        "repair_unlocks_in": " Reparar se desbloquea en {seconds}s.",
        "repair_lock_default_reason": "Reparar queda bloqueado hasta que termine una auditoría válida.",
        "repair_lock_message": "{reason}\n\nEjecutá Auditar, revisá los resultados y volvé acá sólo cuando el plan de reparación esté listo para confirmar.",
        "last_audit_failed": "Última auditoría: {label}. {failed} FAIL / {passed} PASS.{detail_text} Revisá los hallazgos y confirmá cada acción de escritura antes de Reparar.",
        "last_audit_passed_manual": "Última auditoría: {label}. Todos los repositorios seleccionados pasaron.{detail_text} Clasificá hallazgos consultivos antes de publicar; Reparar es opcional y sólo debería aplicar limpiezas revisadas.",
        "last_audit_passed": "Última auditoría: {label}. Todos los repositorios seleccionados pasaron.{detail_text} Reparar es opcional; usalo sólo si todavía querés aplicar acciones de limpieza revisadas.",
        "blocking_category_singular": "{count} categoría bloqueante",
        "blocking_category_plural": "{count} categorías bloqueantes",
        "manual_signal_singular": "{count} señal de revisión manual",
        "manual_signal_plural": "{count} señales de revisión manual",
        "fixture_match_singular": "{count} coincidencia de datos de prueba/documentación mantenida no bloqueante",
        "fixture_match_plural": "{count} coincidencias de datos de prueba/documentación mantenidas no bloqueantes",
        "repair_plan_intro": "Reparar se va a ejecutar con este plan:",
        "active_options": "Opciones activas:",
        "yes": "SÍ",
        "no": "NO",
        "auto_owner": "(auto desde noreply si está disponible)",
        "plan_rewrite_paths": "- Reescribir rutas personales: {value}",
        "plan_replace_text": "- Archivo replace-text explícito: {value}",
        "plan_purge_safe": "- Purgar candidatos seguros (SAFE): {value}",
        "plan_purge_risky": "- Purgar candidatos riesgosos (RISKY): {value}",
        "plan_force_push": "- Push forzado remoto: {value}",
        "plan_open_report": "- Abrir reporte HTML automáticamente: {value}",
        "plan_confirm_each_repo": "- Confirmar reparación por repositorio: {value}",
        "plan_allow_bypass": "- Permitir omisión de push no propietario: {value}",
        "plan_allowed_owners": "- Propietarios permitidos para push: {value}",
        "repair_baseline_changes": "Cambios base de Reparar:",
        "baseline_gitignore": "- Puede agregar patrones faltantes a .gitignore",
        "baseline_untrack": "- Puede quitar del índice con git rm --cached archivos versionados pero ignorados",
        "baseline_rewrite": "- Puede reescribir historial con git-filter-repo según las opciones seleccionadas",
        "risky_warning_1": "ADVERTENCIA: seleccionaste opciones riesgosas (purgar todo, push forzado u omitir la protección de propietario).",
        "risky_warning_2": "Esto puede remover contenido histórico irreversiblemente o saltar protecciones de propietario remoto.",
        "audited_findings_summary": "Resumen explícito de hallazgos auditados:",
        "repo_status_line": "- {name} [{status}]",
        "blocking_categories_line": "  * Categorías bloqueantes: {count}",
        "manual_review_signals_line": "  * Señales de revisión manual: {count}",
        "fixture_context_line": "  * Coincidencias de datos de prueba/documentación mantenidas no bloqueantes: {count}",
        "planned_untrack_line": "  * Quitar del índice planeado (versionado pero ignorado): {count}",
        "planned_path_rewrite_line": "  * Reescritura planeada de rutas personales: {count} hallazgos",
        "personal_paths_disabled": "  * Rutas personales: reescritura deshabilitada",
        "planned_purge_risky_line": "  * Purga riesgosa (RISKY) planeada: {count} candidatos",
        "planned_purge_safe_line": "  * Purga segura (SAFE) planeada: {count} candidatos",
        "more_items": "    - ... y {count} más",
        "secret_purge_disabled": "  * Purga de archivos secretos: deshabilitada",
        "continue_question": "¿Continuar?",
        "rerun_if_changed": "(Si cambiaste la selección u opciones, ejecutá Auditar de nuevo primero.)",
        "dialog_repair_locked_title": "Reparar bloqueado",
        "dialog_repair_locked_review": "Reparar queda disponible sólo después de una auditoría completa y una ventana de revisión de 10 segundos.",
        "dialog_repair_locked_no_results": "Todavía no hay resultados de auditoría en esta sesión. Ejecutá Auditar primero.",
        "dialog_new_audit_required_title": "Se requiere nueva auditoría",
        "dialog_new_audit_required": "La selección actual de repositorios no coincide con la última auditoría. Ejecutá Auditar de nuevo antes de Reparar.",
        "dialog_confirm_repair_title": "Confirmar plan de reparación",
        "dialog_risk_title": "Se requiere aceptación de riesgo",
        "dialog_risk_message": "Seleccionaste opciones riesgosas (purgar todo, push forzado u omitir la protección de propietario).\nConfirmá que aceptás continuar BAJO TU PROPIO RIESGO.",
        "dialog_invalid_git_identity": "Identidad Git inválida",
        "dialog_confirm_global_git_config": "Confirmar configuración Git global",
        "dialog_confirm_global_git_config_message": "Esto actualiza git config --global para todos los repositorios de esta máquina. ¿Continuar?",
        "dialog_global_git_config": "Configuración Git global",
        "dialog_local_git_config": "Configuración Git local",
        "dialog_read_git_identity": "Leer identidad Git",
        "dialog_read_git_identity_select_one": "Seleccioná cero o un repositorio para inspeccionar la identidad Git local/efectiva.",
        "dialog_not_git_repo": "No es un repositorio git: {candidate}",
        "dialog_current_git_identity": "Identidad Git actual",
        "dialog_github_email_settings": "Configuración de email de GitHub",
        "dialog_run_in_progress": "Ejecución en curso",
        "dialog_run_in_progress_message": "Ya hay una ejecución en curso. Esperá a que termine.",
        "dialog_remote_audit_only": "Auditoría remota es solo auditoría",
        "dialog_remote_audit_only_message": "La auditoría remota por propietario u organización de GitHub no puede combinarse con Reparar. Limpiá el propietario u organización de GitHub antes de reparar repositorios locales.",
        "dialog_run_all_title": "Ejecutar en todos los repositorios",
        "dialog_run_all_message": "No hay repositorios seleccionados. ¿Ejecutar {action_name} para todos los repositorios bajo la carpeta raíz?",
        "dialog_invalid_max_matches": "Máx. hallazgos inválido",
        "dialog_invalid_max_matches_message": "Máx. hallazgos debe ser un entero positivo.",
        "dialog_invalid_github_jobs": "Procesos GitHub inválidos",
        "dialog_invalid_github_jobs_message": "Procesos de clonado GitHub debe ser un entero positivo.",
        "action_repair": "reparar",
        "action_audit": "auditar",
        "confirm_repo_repair_title": "Confirmar reparación para este repositorio",
        "confirm_repo_repair_message": "Repositorio {index}/{total}: {repo_name}\n\n¿Aplicar Reparar a este repositorio?\nPodés responder No para omitir sólo este repositorio.",
        "install_github_tooling_title": "Instalar herramientas GitHub",
        "install_github_tooling_intro": "Las verificaciones de endurecimiento GitHub funcionan mejor con GitHub CLI (`gh`) y, en Windows, App Installer / winget funcionando correctamente.",
        "install_github_tooling_confirm": "¿Instalar o reparar esas herramientas ahora?",
        "github_auth_needed_title": "Todavía falta autenticación GitHub",
        "github_auth_needed_message": "GitHub CLI está instalado, pero las verificaciones con token todavía necesitan autenticación.\n\nEjecutá `gh auth login`, o configurá REPO_PRIVACY_GUARDIAN_GITHUB_TOKEN, GITHUB_TOKEN o GH_TOKEN.",
    },
}


def choose_gui_font_family(
    candidates: tuple[str, ...],
    available_families: set[str] | None = None,
) -> str:
    if not candidates:
        raise ValueError("At least one font candidate is required.")

    if available_families:
        lowered = {family.lower() for family in available_families}
        for candidate in candidates:
            if candidate.lower() in lowered:
                return candidate

    return candidates[0]
