"""Shared helpers for country codes and flag emojis.

These functions were previously copy-pasted (with small variations) across
``ala``, ``hand``, ``nb``, ``freesub`` and ``yebe``. They are consolidated here
so there is a single place to maintain the flag <-> country-code <-> name logic.

A flag emoji is two Unicode "regional indicator symbols" (U+1F1E6..U+1F1FF),
one per letter of an ISO 3166-1 alpha-2 code. So ``DE`` <-> 🇩🇪.
"""

import pycountry

# Regional indicator symbol 'A' (U+1F1E6); 'A' is U+0041.
_FLAG_BASE = 0x1F1E6
_ASCII_A = ord("A")
_FLAG_OFFSET = _FLAG_BASE - _ASCII_A  # 127397

DEFAULT_FLAG = "🏳️"

# Sentinel so callers can explicitly request ``None`` as the failure value
# (distinct from "no default given", which falls back to the code/flag itself).
_UNSET = object()

# Alpha-2 codes that pycountry does not resolve the way callers expect.
COMMON_CODE_NAMES = {
    "HK": "Hong Kong",
    "TW": "Taiwan",
    "MO": "Macau",
    "UK": "United Kingdom",
    "US": "United States",
    "RU": "Russia",
    "IR": "Iran",
}


def is_flag_emoji(text):
    """Return True if ``text`` is exactly one flag emoji (two indicator symbols)."""
    return len(text) == 2 and all(_FLAG_BASE <= ord(c) <= _FLAG_BASE + 25 for c in text)


def code_to_flag(country_code):
    """Convert an alpha-2 country code to its flag emoji, or a default flag."""
    code = country_code.upper().strip()
    if len(code) == 2 and code.isalpha():
        return "".join(chr(_FLAG_OFFSET + ord(c)) for c in code)
    return DEFAULT_FLAG


def flag_to_code(flag):
    """Convert a flag emoji back to its alpha-2 country code, or None."""
    if is_flag_emoji(flag):
        return "".join(chr(ord(c) - _FLAG_OFFSET) for c in flag)
    return None


def country_name_from_code(country_code, special_cases=None, default=_UNSET):
    """Resolve an alpha-2 code to a country name.

    ``special_cases`` overrides pycountry for specific codes. When the code is
    unknown, ``default`` is returned if given (may be ``None``), otherwise the
    code itself.
    """
    code = country_code.upper().strip()
    if special_cases and code in special_cases:
        return special_cases[code]
    try:
        country = pycountry.countries.get(alpha_2=code)
    except Exception:
        country = None
    if country:
        return country.name
    return code if default is _UNSET else default


def country_name_from_flag(flag, special_cases=None, default=_UNSET):
    """Resolve a flag emoji to a country name.

    ``special_cases`` (keyed by the emoji) is consulted first, which also lets
    callers map non-flag markers (e.g. ✅). When the flag/code is unknown,
    ``default`` is returned if given (may be ``None``), otherwise the original
    ``flag``.
    """
    if special_cases and flag in special_cases:
        return special_cases[flag]
    fallback = flag if default is _UNSET else default
    code = flag_to_code(flag)
    if code is None:
        return fallback
    return country_name_from_code(code, default=fallback)
