"""Provider-specific intent mappings keyed by canonical authority provider."""

from types import MappingProxyType
from typing import Iterable

from app.providers.catalog import resolve_authority_provider_id


PROVIDER_INTENT_SCOPE_MAP = MappingProxyType({
    "google": MappingProxyType({
        "read_files": ("drive.readonly",), "upload_files": ("drive.file",),
        "read_email": ("gmail.readonly",), "send_email": ("gmail.send",),
        "view_calendar": ("calendar.readonly",), "manage_calendar": ("calendar.events",),
        "read_contacts": ("contacts.readonly",), "read_profile": ("userinfo.profile",),
    }),
    "mock-enterprise": MappingProxyType({
        "read_files": ("content.read",), "write_files": ("content.write",),
        "read_email": ("mail.read",), "send_email": ("mail.send",),
        "view_calendar": ("calendar.read",), "read_profile": ("profile.read",),
    }),
    "mock-code-host": MappingProxyType({
        "read_repositories": ("content.read",), "write_repositories": ("content.write",),
        "create_issues": ("issues.write",), "configure_webhooks": ("webhooks.manage",),
        "read_profile": ("profile.read",),
    }),
})


def normalize_intent(intent: str) -> str:
    return intent.strip().lower().replace("-", "_").replace(" ", "_")


def map_provider_intents(provider: str, actions: Iterable[str]) -> tuple[list[str], list[str]]:
    canonical = resolve_authority_provider_id(provider)
    mapping = PROVIDER_INTENT_SCOPE_MAP[canonical]
    required: set[str] = set()
    unknown: list[str] = []
    
    # Common semantic synonyms for natural language matching
    synonyms = {
        "file": "read_files",
        "files": "read_files",
        "document": "read_files",
        "documents": "read_files",
        "read": "read_files",
        "view": "read_files",
        "email": "read_email",
        "mail": "read_email",
        "calendar": "view_calendar",
        "contact": "read_contacts",
        "contacts": "read_contacts",
        "profile": "read_profile",
        "repo": "read_repositories",
        "repositories": "read_repositories",
        "issue": "create_issues",
        "issues": "create_issues",
        "webhook": "configure_webhooks",
        "webhooks": "configure_webhooks",
    }

    for action in actions:
        normalized = normalize_intent(action)
        # 1. Exact match
        scopes = mapping.get(normalized)
        if scopes:
            required.update(scopes)
            continue
        
        # 2. Check if known key is contained in normalized action
        found_known = False
        for key, scps in mapping.items():
            if key in normalized or normalized in key:
                required.update(scps)
                found_known = True
                break
        if found_known:
            continue
            
        # 3. Word token matching with synonyms
        words = normalized.split("_")
        matched_from_words = False
        for word in words:
            if word in synonyms and synonyms[word] in mapping:
                required.update(mapping[synonyms[word]])
                matched_from_words = True
                break
        
        if not matched_from_words:
            unknown.append(action)

    return sorted(required), unknown
