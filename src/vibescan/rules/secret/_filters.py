"""Shared false-positive filters for secret detection rules."""

from __future__ import annotations

import re

# Values that are clearly NOT secrets
_SAFE_VALUE = re.compile(
    r'(?:'
    r'[\u3131-\uD79D]'                          # Korean characters
    r'|[\u3000-\u303F\u4E00-\u9FFF\uFF00-\uFFEF]'  # CJK characters
    r'|\s{3,}'                                   # 3+ consecutive spaces (sentence)
    r'|^(?:your|my|the|change|enter|replace|update|set|put|insert|'
    r'example|default|placeholder|test|none|null|undefined|todo|fixme|'
    r'xxx|sample|demo|mock|stub|fake|dummy|temp|tmp)[\s_\-]'  # placeholder prefixes
    r'|^\*+$'                                    # all asterisks
    r'|^\.{3,}$'                                 # all dots
    r'|^<.*>$'                                   # <your-password>
    r'|^\{.*\}$'                                 # {your_password}
    r'|^x{4,}$'                                  # xxxx placeholders
    r')',
    re.IGNORECASE,
)

# Environment variable references — not hardcoded secrets
_ENV_VAR_REF = re.compile(
    r'(?:'
    r'\$\{[A-Z_][A-Z0-9_]*\}'        # ${VAR_NAME}
    r'|\$\(\([^)]+\)\)'               # $((expr))
    r'|\$\([A-Z_][A-Z0-9_]*\)'       # $(VAR_NAME)
    r'|\$\{\{\s*secrets\.[^}]+\}\}'   # ${{ secrets.VAR }}
    r'|\$[A-Z_][A-Z0-9_]*'           # $VAR_NAME
    r')',
    re.IGNORECASE,
)


def is_false_positive_value(value: str) -> bool:
    """Return True if the matched value is clearly not a real secret."""
    return bool(_SAFE_VALUE.search(value))


def contains_env_var_ref(line: str) -> bool:
    """Return True if the line contains environment variable references."""
    return bool(_ENV_VAR_REF.search(line))
