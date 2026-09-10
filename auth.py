from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from runner import ShroodlerJob

_UNAUTHENTICATED = "unauthenticated"
_MAX_SELECT = 24  # Discord select max 25, one slot reserved for unauthenticated

_OWNER_JAR_NAMES = (
    "owner.json",
    "owner-cookies.json",
    "cookies.json",
    "storagestate.json",
    "owner.storagestate.json",
)
_PEER_JAR_NAMES = (
    "peer.json",
    "peer-cookies.json",
    "peer.storagestate.json",
)
_LOGIN_NAMES = (
    "login.json",
    "login-recipe.json",
    "owner-login.json",
    "recipe.json",
)
_PEER_LOGIN_NAMES = (
    "peer-login.json",
    "peer-recipe.json",
)

_FLAT_ROLE = re.compile(
    r"^(?P<stem>.+)\.(?P<role>owner|peer|login|peer-login|peer_login)(?:\.[A-Za-z0-9]+)?$",
    re.I,
)


@dataclass
class AuthPayload:
    name: str = _UNAUTHENTICATED
    login_recipe: Path | None = None
    peer_recipe: Path | None = None
    owner_jar: Path | None = None
    peer_jar: Path | None = None

    def has_any(self) -> bool:
        return any(
            [
                self.login_recipe,
                self.peer_recipe,
                self.owner_jar,
                self.peer_jar,
            ]
        )

    def summary(self) -> str:
        if not self.has_any():
            return "unauthenticated"
        bits: list[str] = []
        if self.owner_jar:
            bits.append("owner session")
        if self.peer_jar:
            bits.append("peer session")
        if self.login_recipe:
            bits.append("owner login recipe")
        if self.peer_recipe:
            bits.append("peer login recipe")
        detail = ", ".join(bits)
        return f"{self.name} ({detail})" if detail else self.name


@dataclass(frozen=True)
class SessionProfile:
    id: str
    owner_jar: Path | None = None
    peer_jar: Path | None = None
    login_recipe: Path | None = None
    peer_recipe: Path | None = None
    hosts: tuple[str, ...] = ()

    def matches(self, hostname: str) -> bool:
        host = hostname.rstrip(".").lower()
        for pattern in self.hosts:
            if hostname_matches(pattern, host):
                return True
        return False

    def to_auth(self) -> AuthPayload:
        return AuthPayload(
            name=self.id,
            login_recipe=self.login_recipe,
            peer_recipe=self.peer_recipe,
            owner_jar=self.owner_jar,
            peer_jar=self.peer_jar,
        )

    def description(self) -> str:
        bits: list[str] = []
        if self.owner_jar:
            bits.append("owner jar")
        if self.peer_jar:
            bits.append("peer jar")
        if self.login_recipe:
            bits.append("login recipe")
        if self.peer_recipe:
            bits.append("peer recipe")
        return ", ".join(bits) or "empty"


def hostname_matches(pattern: str, hostname: str) -> bool:
    p = pattern.strip().rstrip(".").lower()
    h = hostname.strip().rstrip(".").lower()
    if not p or not h:
        return False
    if p.startswith("*."):
        suffix = p[1:]  # .example.com
        return h.endswith(suffix) or h == p[2:]
    return h == p or h.endswith("." + p)


def _looks_like_hostname(name: str) -> bool:
    return "." in name and " " not in name and not name.startswith(".")


def _case_file(directory: Path, names: tuple[str, ...]) -> Path | None:
    available = {p.name.lower(): p for p in directory.iterdir() if p.is_file()}
    for name in names:
        found = available.get(name.lower())
        if found is not None:
            return found
    return None


def _read_hosts(directory: Path, fallback: tuple[str, ...]) -> tuple[str, ...]:
    for candidate in ("hosts.txt", "hosts"):
        path = directory / candidate
        if not path.is_file():
            continue
        hosts: list[str] = []
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line and not line.startswith("#"):
                hosts.append(line)
        return tuple(hosts)
    return fallback


def _profile_from_dir(directory: Path) -> SessionProfile | None:
    owner_jar = _case_file(directory, _OWNER_JAR_NAMES)
    peer_jar = _case_file(directory, _PEER_JAR_NAMES)
    login_recipe = _case_file(directory, _LOGIN_NAMES)
    peer_recipe = _case_file(directory, _PEER_LOGIN_NAMES)
    if not any((owner_jar, peer_jar, login_recipe, peer_recipe)):
        return None
    fallback = (directory.name,) if _looks_like_hostname(directory.name) else ()
    return SessionProfile(
        id=directory.name,
        owner_jar=owner_jar,
        peer_jar=peer_jar,
        login_recipe=login_recipe,
        peer_recipe=peer_recipe,
        hosts=_read_hosts(directory, fallback),
    )


def _flat_profiles(sessions_dir: Path, used_ids: set[str]) -> list[SessionProfile]:
    grouped: dict[str, dict[str, Path]] = {}
    for path in sessions_dir.iterdir():
        if not path.is_file():
            continue
        match = _FLAT_ROLE.match(path.name)
        if not match:
            continue
        stem = match.group("stem")
        role = match.group("role").lower().replace("_", "-")
        grouped.setdefault(stem, {})[role] = path

    profiles: list[SessionProfile] = []
    for stem, roles in sorted(grouped.items()):
        if stem in used_ids:
            continue
        owner_jar = roles.get("owner")
        peer_jar = roles.get("peer")
        login_recipe = roles.get("login")
        peer_recipe = roles.get("peer-login")
        if not any((owner_jar, peer_jar, login_recipe, peer_recipe)):
            continue
        hosts = (stem,) if _looks_like_hostname(stem) else ()
        profiles.append(
            SessionProfile(
                id=stem,
                owner_jar=owner_jar,
                peer_jar=peer_jar,
                login_recipe=login_recipe,
                peer_recipe=peer_recipe,
                hosts=hosts,
            )
        )
    return profiles


def list_profiles(sessions_dir: Path) -> list[SessionProfile]:
    sessions_dir.mkdir(parents=True, exist_ok=True)
    profiles: list[SessionProfile] = []
    used: set[str] = set()
    for child in sorted(sessions_dir.iterdir(), key=lambda p: p.name.lower()):
        if not child.is_dir() or child.name.startswith("."):
            continue
        profile = _profile_from_dir(child)
        if profile is None:
            continue
        profiles.append(profile)
        used.add(profile.id)
    profiles.extend(_flat_profiles(sessions_dir, used))
    return profiles


def default_profile(profiles: list[SessionProfile], hostname: str) -> SessionProfile | None:
    matches = [p for p in profiles if p.matches(hostname)]
    if not matches:
        return None
    matches.sort(key=lambda p: max((len(h) for h in p.hosts), default=0), reverse=True)
    return matches[0]


def profiles_for_select(
    profiles: list[SessionProfile],
    hostname: str,
) -> list[SessionProfile]:
    if len(profiles) <= _MAX_SELECT:
        return profiles
    matching = [p for p in profiles if p.matches(hostname)]
    matched_ids = {p.id for p in matching}
    rest = [p for p in profiles if p.id not in matched_ids]
    return (matching + rest)[:_MAX_SELECT]


def resolve_auth(
    sessions_dir: Path,
    hostname: str,
    session: str | None,
) -> tuple[AuthPayload, str | None]:
    profiles = list_profiles(sessions_dir)
    chosen = (session or "").strip()
    if not chosen:
        matched = default_profile(profiles, hostname)
        return (matched.to_auth() if matched else AuthPayload()), None
    if chosen.lower() == _UNAUTHENTICATED:
        return AuthPayload(), None
    by_id = {item.id.lower(): item for item in profiles}
    profile = by_id.get(chosen.lower())
    if profile is None:
        return AuthPayload(), f"unknown session `{chosen}`"
    return profile.to_auth(), None


def apply_auth(job: ShroodlerJob, payload: AuthPayload) -> None:
    job.login_recipe = payload.login_recipe
    job.peer_recipe = payload.peer_recipe
    job.owner_jar = payload.owner_jar
    job.peer_jar = payload.peer_jar
    job.auth_label = payload.summary()
