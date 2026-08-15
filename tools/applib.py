#!/usr/bin/env python3
"""Resolve one exact host/URL to its per-application target brain.

This is a library rather than a second state store.  The application directory and the
identity in ``map.md`` remain authoritative; callers use these helpers so preflight, brief and
the CLI cannot each invent a different host-to-directory rule.
"""
from dataclasses import dataclass
import hashlib
import ipaddress
import re
import shutil
import uuid
from pathlib import Path
from urllib.parse import urlsplit


FILES = ("map.md", "endpoints.md", "notes.md")
MAP_HEADING = re.compile(r"^#\s+(.+?)\s+[—–]\s+Application Map\s*$", re.M)
TAGGED_NOTE = re.compile(r"^\s*-\s+(?:FACT|HYPOTHESIS|ASSUMPTION|NOTE|CONTEXT)\s*:", re.I | re.M)


@dataclass(frozen=True)
class AppSubject:
    host: str
    port: int | None = None

    @property
    def display(self):
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}" if self.port is not None else host

    @property
    def slug(self):
        if ":" in self.host:
            host = "ipv6-" + hashlib.sha256(self.host.encode()).hexdigest()[:12]
        else:
            host = self.host
        return f"{host}-{self.port}" if self.port is not None else host


@dataclass(frozen=True)
class AppResolution:
    subject: AppSubject
    status: str
    path: Path | None
    candidates: tuple[Path, ...] = ()

    @property
    def populated(self):
        return self.path is not None and app_has_data(self.path)

    @property
    def state(self):
        if self.status != "found":
            return self.status
        return "populated" if self.populated else "scaffold"

    def files(self):
        if self.path is None:
            return ()
        return tuple(self.path / name for name in FILES if (self.path / name).is_file())


def parse_subject(raw):
    """Parse a URL, hostname, IP, or host:port without accepting a path as a host."""
    subject_text = str(raw or "").strip()
    if not subject_text or any(character.isspace() for character in subject_text):
        raise ValueError("application subject must be one URL, host, IP, or host:port")

    parsed = urlsplit(subject_text if "://" in subject_text else "//" + subject_text)
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("application subject must not contain credentials")
    if not parsed.hostname:
        raise ValueError(f"cannot find a host in {subject_text!r}")
    if "://" not in subject_text and (parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        raise ValueError("a subject containing a path must be a full URL")
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError(f"invalid port in {subject_text!r}: {error}") from error

    host = parsed.hostname.rstrip(".").lower()
    if not host:
        raise ValueError(f"cannot find a host in {subject_text!r}")
    if ":" in host:
        try:
            host = ipaddress.ip_address(host).compressed
        except ValueError as error:
            raise ValueError(f"invalid IPv6 address {host!r}") from error
    else:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as error:
            raise ValueError(f"invalid hostname {host!r}") from error
        if not re.fullmatch(r"[a-z0-9._-]+", host):
            raise ValueError(f"invalid hostname {host!r}")
    return AppSubject(host, port)


def identity_from_map(app_dir):
    path = Path(app_dir) / "map.md"
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return None
    match = MAP_HEADING.search(text)
    if not match or "<host>" in match.group(1):
        return None
    try:
        return parse_subject(match.group(1))
    except ValueError:
        return None


def application_dirs(target):
    root = Path(target) / "applications"
    if not root.is_dir():
        return ()
    return tuple(sorted(
        path for path in root.iterdir()
        if path.is_dir() and not path.name.startswith(("_", "."))
    ))


def _matches(target, subject):
    matches = []
    for path in application_dirs(target):
        identity = identity_from_map(path)
        if identity and identity.host == subject.host:
            matches.append((path, identity.port))
            continue
        # A newly-created or partly-written brain may not yet have a readable heading.  Its
        # canonical directory name is still enough for an exact match; never fuzzy-match it.
        if path.name == AppSubject(subject.host, subject.port).slug:
            matches.append((path, subject.port))
        elif subject.port is not None and path.name == AppSubject(subject.host).slug:
            matches.append((path, None))
    return matches


def resolve(target, raw_subject):
    """Return a deterministic resolution; never silently pick between two ports."""
    subject = parse_subject(raw_subject)
    matches = _matches(target, subject)
    if subject.port is not None:
        exact = [path for path, port in matches if port == subject.port]
        generic = [path for path, port in matches if port is None]
        selected = exact or generic
    else:
        generic = [path for path, port in matches if port is None]
        selected = generic or [path for path, _port in matches]

    # Preserve order while removing a path found through both its heading and canonical slug.
    selected = list(dict.fromkeys(selected))
    if len(selected) == 1:
        return AppResolution(subject, "found", selected[0], tuple(selected))
    if len(selected) > 1:
        return AppResolution(subject, "ambiguous", None, tuple(selected))
    return AppResolution(subject, "missing", None)


def _table_has_data(text):
    for line in text.splitlines():
        stripped = line.strip()
        if not (stripped.startswith("|") and stripped.endswith("|")):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if cells and all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
            continue
        lowered = {re.sub(r"[*`]", "", cell).lower() for cell in cells}
        if {"role", "url", "feature"} & lowered:
            continue
        if any(cell and not re.fullmatch(r"[—-]", cell) and "<" not in cell for cell in cells):
            return True
    return False


def app_has_data(app_dir):
    """Distinguish a copied scaffold from an application brain with durable facts."""
    directory = Path(app_dir)
    for name in FILES:
        try:
            text = (directory / name).read_text(encoding="utf-8-sig", errors="replace")
        except OSError:
            continue
        if _table_has_data(text) or TAGGED_NOTE.search(text):
            return True
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("- ") and "<" not in stripped and stripped != "-":
                return True
    return False


def _create_scaffold(template, destination, display):
    temporary = destination.parent / f".{destination.name}.tmp-{uuid.uuid4().hex}"
    try:
        shutil.copytree(template, temporary)
        for name in FILES:
            path = temporary / name
            if path.is_file():
                text = path.read_text(encoding="utf-8-sig").replace("<host>", display)
                path.write_text(text, encoding="utf-8")
        temporary.rename(destination)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def ensure(target, raw_subject):
    """Atomically create a per-app scaffold, or return the existing exact brain."""
    target = Path(target)
    if not (target / "index.md").is_file():
        raise ValueError(f"{target} is not a target brain (no index.md)")
    resolution = resolve(target, raw_subject)
    if resolution.status == "found":
        return resolution
    if resolution.status == "ambiguous":
        names = ", ".join(path.name for path in resolution.candidates)
        raise ValueError(
            f"{resolution.subject.display} matches multiple app brains: {names}; supply a port")

    template = target / "applications" / "_host-template"
    if not template.is_dir():
        raise ValueError(f"application template is missing: {template}")
    destination = target / "applications" / resolution.subject.slug
    _create_scaffold(template, destination, resolution.subject.display)
    return AppResolution(resolution.subject, "found", destination, (destination,))
