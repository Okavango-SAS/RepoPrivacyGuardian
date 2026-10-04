"""Shared redaction patterns without coordinator or runtime dependencies."""

from __future__ import annotations

import re

DEFAULT_PLACEHOLDER = "redacted-contributor@example.invalid"

REDACTED_EMAIL = "<redacted-email>"

REDACTED_IDENTITY_TOKEN = "<redacted-identity-token>"

# Redaction placeholder, not a credential.
REDACTED_SECRET = "<redacted-secret>"  # nosec B105

REDACTED_PATH = "<redacted-path>"

EMAIL_NOISE_DOMAINS = {
    "example.com",
    "example.org",
    "example.net",
    "localhost",
    "localdomain",
}

SSH_REMOTE_PSEUDO_EMAILS = {
    ("git", "github.com"),
    ("git", "ssh.github.com"),
    ("git", "gitlab.com"),
    ("git", "bitbucket.org"),
    ("git", "ssh.dev.azure.com"),
    ("git", "vs-ssh.visualstudio.com"),
    ("hg", "bitbucket.org"),
}

# Keep committed environment templates separate from actual environment files.
ENV_SENSITIVE_FILENAME_RE = r"(^|/)\.env(?:\.(?!example$)[^/]+)?$"

SENSITIVE_FILENAME_RE = re.compile(
    ENV_SENSITIVE_FILENAME_RE
    + r"|"
    r"\.pem$|\.key$|\.p12$|\.pfx$|\.kdbx$|"
    r"(^|/)id_(?:rsa|dsa|ecdsa|ed25519)$|"
    r"(^|/)\.(?:npmrc|pypirc|netrc|dockercfg)$|"
    r"(^|/)\.docker/config\.json$|"
    r"(^|/)\.aws/credentials$|"
    r"(^|/)\.kube/config$|"
    r"(^|/)kubeconfig$|"
    r"(^|/)(secrets?|credentials?|token)([._-]|$)|"
    r"(^|/)__pycache__(/|$)|"
    r"\.pyc$",
    re.IGNORECASE,
)

HIGH_CONFIDENCE_SECRET_CONTENT_RE = re.compile(
    r"gh[opsru]_[A-Za-z0-9]{36,}|"
    r"github_pat_[A-Za-z0-9_]{40,}|"
    r"\bgl(?:pat|oas|dt|rtr|rt|cbt|ptt|ft|imt|agent|wt|soat)-[A-Za-z0-9_-]{16,}\b|"
    r"\bcf(?:k|ut|at)_[A-Za-z0-9]{40,}\b|"
    r"AKIA[0-9A-Z]{16}|"
    r"(?i:aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?|"
    r"AIza[0-9A-Za-z\-_]{35}|"
    r"\bya29\.[0-9A-Za-z\-_]{32,}\b|"
    r"\bsk-(?:proj|svcacct)-[A-Za-z0-9_-]{32,}\b|"
    r"\bsk-ant-(?:api\d{2}-|admin)[A-Za-z0-9_-]{20,}\b|"
    r"x(?:ox[baprs]|app|wfp)-[A-Za-z0-9-]+|"
    r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+|"
    r"https://discord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_-]{32,}|"
    r"(?:sk|rk)_live_[0-9A-Za-z]{24,}|"
    r"SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}|"
    r"npm_[A-Za-z0-9]{36}|"
    r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b|"
    r"\b[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}\b|"
    r"(?i:heroku[_-]?api[_-]?key)\s*[=:]\s*['\"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]?|"
    r"(?i:(?:AccountKey|storage[_-]?key))\s*[=:]\s*['\"]?[A-Za-z0-9+/=]{88}['\"]?|"
    r"(?i:cloudflare[_-]?(?:api[_-]?)?(?:token|key))\s*[=:]\s*['\"]?[A-Za-z0-9_-]{37,64}['\"]?|"
    r"(?i:datadog[_-]?(?:api|app(?:lication)?)?[_-]?key)\s*[=:]\s*['\"]?[0-9a-f]{32,40}['\"]?|"
    r"(?i:twilio[_-]?auth[_-]?token)\s*[=:]\s*['\"]?[0-9a-f]{32}['\"]?|"
    r"(?i:mailgun[_-]?api[_-]?key)\s*[=:]\s*['\"]?key-[0-9a-f]{32}['\"]?|"
    r"(?i:\b(?:https?|ssh|ftp|ftps|sftp|mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|rediss|amqp|amqps)://[^\s:/?#'\"`<>]+:[^\s@'\"`<>]{3,}@[^\s'\"`<>]+)|"
    r"(?i:\bauthorization\s*:\s*(?:bearer|token|basic)\s+[A-Za-z0-9._~+/=-]{16,})|"
    r"BEGIN (RSA|OPENSSH|EC|DSA|PGP) PRIVATE KEY"
)

SECRET_CONTENT_RE = HIGH_CONFIDENCE_SECRET_CONTENT_RE

LOW_CONFIDENCE_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(?P<key>\b(?:password|passwd|pwd|passphrase|secret|api[_-]?key|apikey|"
    r"access[_-]?token|auth[_-]?token|refresh[_-]?token|client[_-]?secret|"
    r"private[_-]?key|connection[_-]?string|webhook[_-]?url|dsn)\b)"
    r"(?P<sep>\s*(?:=|:)\s*)"
    r"(?P<quote>['\"]?)"
    r"(?P<value>[A-Za-z0-9][A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]{12,})"
    r"(?P=quote)"
)

SECRET_FIXTURE_PATH_RE = re.compile(
    r"(^|/)(test|tests|fixture|fixtures|mock|mocks|sample|samples|demo|spec|benchmarks?)(/|$)",
    re.IGNORECASE,
)

SECRET_DOCUMENTATION_PATH_RE = re.compile(r"(^|/)(docs?|examples?)(/|$)", re.IGNORECASE)

SECRET_DOCUMENTATION_FILE_RE = re.compile(
    r"readme|changelog|contributing|copilot|instructions|policy|roadmap|"
    r"checklist|known_issues|lessons|operations|troubleshooting|versioning",
    re.IGNORECASE,
)

SECRET_SAFE_PLACEHOLDER_RE = re.compile(
    r"(?i)\b(?:example|sample|dummy|fake|fixture|mock|placeholder|redacted|"
    r"changeme|change-me|not-a-real|your[_-]?(?:token|key|secret|password)|"
    r"insert[_-]?here|todo|example\.invalid|localhost)\b|"
    r"<[^>\n]{1,80}>|"
    r"\$\{[A-Za-z0-9_:-]{1,80}\}|"
    r"%[A-Za-z0-9_]{1,80}%|"
    r"\b[A-Z0-9_]{2,}_(?:TOKEN|KEY|SECRET|PASSWORD)\b|"
    r"\b(?:x{8,}|a{16,}|b{16,}|c{16,}|0{16,})\b|"
    r"([A-Za-z0-9])\1{15,}"
)

SECRET_REMEDIATE_FILENAME_RE = re.compile(
    ENV_SENSITIVE_FILENAME_RE
    + r"|"
    r"\.pem$|\.key$|\.p12$|\.pfx$|\.kdbx$|"
    r"(^|/)id_(?:rsa|dsa|ecdsa|ed25519)$|"
    r"(^|/)\.(?:npmrc|pypirc|netrc|dockercfg)$|"
    r"(^|/)\.docker/config\.json$|"
    r"(^|/)\.aws/credentials$|"
    r"(^|/)\.kube/config$|"
    r"(^|/)kubeconfig$|"
    r"(^|/)(secret|credential|token|password|passwd|api[_-]?key)([._-]|$)",
    re.IGNORECASE,
)

PERSONAL_PATH_RE = re.compile(
    r"(?i)"
    r"[A-Za-z]:(?:\\\\|\\|/)(?:Users|Documents and Settings|home)(?:\\\\|\\|/)[A-Za-z0-9][A-Za-z0-9._-]*"
    r"|/(?:Users|home)/[A-Za-z0-9][A-Za-z0-9._-]*"
)

PERSONAL_PATH_LITERAL_PATTERNS = (
    re.compile(
        r"(?i)[A-Za-z]:/(?:Users|home)/[A-Za-z0-9][A-Za-z0-9._-]*"
        r"(?:/[^\s\"'`<>|]+){0,8}"
    ),
    re.compile(
        r"(?i)[A-Za-z]:\\(?:Users|home)\\[A-Za-z0-9][A-Za-z0-9._-]*"
        r"(?:\\[^\s\"'`<>|]+){0,8}"
    ),
    re.compile(
        r"(?i)[A-Za-z]:\\\\(?:Users|home)\\\\[A-Za-z0-9][A-Za-z0-9._-]*"
        r"(?:\\\\[^\s\"'`<>|]+){0,8}"
    ),
    re.compile(
        r"(?i)/(?:Users|home)/[A-Za-z0-9][A-Za-z0-9._-]*"
        r"(?:/[^\s\"'`<>|]+){0,8}"
    ),
)

EMAIL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

SIMPLE_EMAIL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

EMAIL_FIXTURE_PATH_RE = re.compile(
    r"(^|/)(test|tests|fixture|fixtures|mock|mocks|sample|samples|demo|benchmarks?|spec)(/|$)",
    re.IGNORECASE,
)

EMAIL_FIXTURE_SNIPPET_RE = re.compile(
    r"\b(mock|fixture|dummy|sample|placeholder|test|assert|expect|pytest|unittest)\b|"
    r"vi\.spyon|mockresolvedvalue|auth\.login\(",
    re.IGNORECASE,
)

EMAIL_LOW_CONFIDENCE_PATH_RE = re.compile(
    r"(^|/)(test|tests|docs|doc|example|examples|fixture|fixtures|mock|mocks|"
    r"sample|samples|demo|benchmarks?|spec)(/|$)",
    re.IGNORECASE,
)

EMAIL_LOW_CONFIDENCE_FILE_RE = re.compile(
    r"readme|changelog|contributing|copilot|instructions|policy|roadmap|"
    r"checklist|known_issues|lessons",
    re.IGNORECASE,
)

EMAIL_LOW_CONFIDENCE_SNIPPET_RE = re.compile(
    r"\b(mock|fixture|dummy|sample|placeholder|test|assert|expect|pytest|unittest)\b|"
    r"vi\.spyon|mockresolvedvalue|auth\.login\(|next_public_support_email",
    re.IGNORECASE,
)
