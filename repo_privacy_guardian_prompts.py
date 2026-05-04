from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


PROMPT_LOCALE_DEFAULT = "en"
PROMPT_LOCALE_FALLBACK = "es-419"


@dataclass(frozen=True)
class AgenticPrompt:
    prompt_id: str
    locale: str
    title: str
    description: str
    relative_path: str
    command: str

    def path(self, repo_root: Path) -> Path:
        return repo_root / self.relative_path


PROMPT_REGISTRY: tuple[AgenticPrompt, ...] = (
    AgenticPrompt(
        prompt_id="environment_setup",
        locale="en",
        title="Prepare the local environment",
        description="Use after cloning Repo Privacy Guardian to install the package and verify tooling without auditing other repositories.",
        relative_path="docs/prompts/en/06_AGENTIC_ENVIRONMENT_SETUP.prompt.md",
        command="repo-privacy-guardian --check-tooling",
    ),
    AgenticPrompt(
        prompt_id="audit_only",
        locale="en",
        title="Audit another repository",
        description="Run a defensive audit-only pass, classify findings, and preserve redacted evidence before any repair work.",
        relative_path="docs/prompts/en/05_DOGFOODING_AUDIT_ONLY.prompt.md",
        command="repo-privacy-guardian --root <repos-root> --repos <target-repo> --dry-run --yes",
    ),
    AgenticPrompt(
        prompt_id="audit_and_repair",
        locale="en",
        title="Audit and repair after approval",
        description="Use when the operator has reviewed findings and wants an agent to preview, apply approved fixes, and re-audit.",
        relative_path="docs/prompts/en/07_AGENTIC_AUDIT_AND_REPAIR.prompt.md",
        command="repo-privacy-guardian --root <repos-root> --repos <target-repo> --fix --dry-run --yes",
    ),
    AgenticPrompt(
        prompt_id="cli_workflow",
        locale="en",
        title="Agentic CLI workflow",
        description="A compact end-to-end CLI delegation prompt for release/security work in Codex, Claude Code, Cursor, GitHub Copilot, Antigravity, or similar tools.",
        relative_path="docs/prompts/en/04_AGENTIC_CLI_EXECUTION.prompt.md",
        command="repo-privacy-guardian --root <repos-root> --repos <target-repo> --dry-run --yes --audit-github-hardening",
    ),
    AgenticPrompt(
        prompt_id="environment_setup",
        locale="es-419",
        title="Preparar el entorno local",
        description="Usar después de clonar Repo Privacy Guardian para instalar el paquete y verificar herramientas sin auditar otros repositorios.",
        relative_path="docs/prompts/06_PREPARACION_ENTORNO_AGENTICA.prompt.md",
        command="repo-privacy-guardian --check-tooling",
    ),
    AgenticPrompt(
        prompt_id="audit_only",
        locale="es-419",
        title="Auditar otro repositorio",
        description="Ejecutar una pasada defensiva de solo auditoría, clasificar hallazgos y preservar evidencia redactada antes de cualquier reparación.",
        relative_path="docs/prompts/05_DOGFOODING_AUDIT_ONLY.prompt.md",
        command="repo-privacy-guardian --root <repos-root> --repos <target-repo> --dry-run --yes",
    ),
    AgenticPrompt(
        prompt_id="audit_and_repair",
        locale="es-419",
        title="Auditar y reparar con aprobación",
        description="Usar cuando el operador ya revisó hallazgos y quiere que un agente previsualice, aplique correcciones aprobadas y vuelva a auditar.",
        relative_path="docs/prompts/07_AUDITORIA_REPARACION_AGENTICA.prompt.md",
        command="repo-privacy-guardian --root <repos-root> --repos <target-repo> --fix --dry-run --yes",
    ),
    AgenticPrompt(
        prompt_id="cli_workflow",
        locale="es-419",
        title="Flujo CLI agéntico",
        description="Instrucción compacta para delegar un flujo CLI de publicación y seguridad en Codex, Claude Code, Cursor, GitHub Copilot, Antigravity o herramientas similares.",
        relative_path="docs/prompts/04_EJECUCION_AGENTICA_CLI.prompt.md",
        command="repo-privacy-guardian --root <repos-root> --repos <target-repo> --dry-run --yes --audit-github-hardening",
    ),
)


def normalize_prompt_locale(locale: str | None) -> str:
    if not locale:
        return PROMPT_LOCALE_DEFAULT
    normalized = str(locale).strip().lower().replace("_", "-")
    if normalized in {"es", "es-419", "es-ar", "es-mx", "es-cl", "es-co"}:
        return PROMPT_LOCALE_FALLBACK
    return PROMPT_LOCALE_DEFAULT


def agentic_prompt_cards(locale: str | None) -> tuple[AgenticPrompt, ...]:
    requested_locale = normalize_prompt_locale(locale)
    fallback_by_id = {
        prompt.prompt_id: prompt
        for prompt in PROMPT_REGISTRY
        if prompt.locale == PROMPT_LOCALE_FALLBACK
    }
    requested_by_id = {
        prompt.prompt_id: prompt
        for prompt in PROMPT_REGISTRY
        if prompt.locale == requested_locale
    }

    ordered_ids = ("environment_setup", "audit_only", "audit_and_repair", "cli_workflow")
    return tuple(
        requested_by_id.get(prompt_id) or fallback_by_id[prompt_id]
        for prompt_id in ordered_ids
    )


def read_prompt_text(prompt: AgenticPrompt, repo_root: Path) -> str:
    return prompt.path(repo_root).read_text(encoding="utf-8")
