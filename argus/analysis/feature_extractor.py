# A.R.G.U.S. — Automated Real-time Guardian for User Systems
# Copyright (C) 2026  MdZeeshan-ML | GPL v3
"""
Feature extractor — transforms raw file/email events into structured metadata
ready for the LLM inference prompt.

Privacy rule: reads file bytes locally only. Feature dict (metadata) is what
travels to inference. File contents never leave this module.
"""

import hashlib
import ipaddress
import json
import logging
import math
import subprocess
import threading
import time
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

log = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Extension classification constants (imported by gate_keeper.py)
# ------------------------------------------------------------------

# Files that require the dynamic analysis gate (Gate 3)
GATE3_EXTENSIONS: frozenset[str] = frozenset({
    # Native executables
    '.exe', '.dll', '.scr', '.com', '.pif', '.msi',
    # Script hosts
    '.py', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.wsf', '.hta', '.sh',
    # Registry / config execution
    '.reg', '.msc',
    # Shortcuts — static target analysis only, never execute
    '.lnk', '.url',
    # Office macro-enabled formats
    '.docm', '.xlsm', '.pptm', '.xll', '.iqy', '.slk',
    # Disk images — mount + scan, not execute
    '.iso', '.img',
    # Java
    '.jar',
})

# Never run these natively — static gates + HUMAN_DECISION_REQUIRED
NEVER_EXECUTE_NATIVELY: frozenset[str] = frozenset({
    '.exe', '.dll', '.scr', '.com', '.pif', '.msi', '.hta', '.jar',
})

# Read the target path and analyze that; don't execute the shortcut itself
STATIC_ANALYSIS_ONLY: frozenset[str] = frozenset({
    '.lnk', '.url',
})

# Category labels per extension group — injected into features dict for LLM context
_GATE3_CATEGORY_MAP: dict[str, str] = {
    **{ext: "executable" for ext in {'.exe', '.dll', '.scr', '.com', '.pif', '.msi'}},
    **{ext: "script"     for ext in {'.py', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.wsf', '.hta', '.sh'}},
    **{ext: "registry"   for ext in {'.reg', '.msc'}},
    **{ext: "shortcut"   for ext in {'.lnk', '.url'}},
    **{ext: "office_macro" for ext in {'.docm', '.xlsm', '.pptm', '.xll', '.iqy', '.slk'}},
    **{ext: "archive_image" for ext in {'.iso', '.img'}},
    '.jar': "java",
}

# First-4-byte signatures for quick independent check alongside python-magic
_MAGIC_SIGS: dict[bytes, str] = {
    b'\x4d\x5a':         "PE executable (MZ)",
    b'\x7f\x45\x4c\x46': "ELF executable",
    b'\x25\x50\x44\x46': "PDF",
    b'\x50\x4b\x03\x04': "ZIP / Office OOXML",
    b'\xd0\xcf\x11\xe0': "OLE Compound Document",
    b'\x7b\x5c\x72\x74': "Rich Text Format",
}

# B1: max WHOIS lookups for link domains per message (rate budget)
MAX_LINK_WHOIS: int = 5

# B2: known URL-shortening services — flag only, never fetch/resolve
_KNOWN_SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "short.io", "rebrand.ly", "is.gd", "v.gd", "tiny.cc", "shorte.st",
    "adf.ly", "bc.vc", "linktr.ee", "go2l.ink",
})

# Extension → acceptable MIME types (populated for mismatch detection)
_EXT_EXPECTED_MIMES: dict[str, frozenset[str]] = {
    '.pdf':  frozenset({'application/pdf'}),
    '.png':  frozenset({'image/png'}),
    '.jpg':  frozenset({'image/jpeg'}),
    '.jpeg': frozenset({'image/jpeg'}),
    '.gif':  frozenset({'image/gif'}),
    '.zip':  frozenset({'application/zip'}),
    '.exe':  frozenset({'application/x-dosexec', 'application/x-msdownload', 'application/octet-stream'}),
    '.dll':  frozenset({'application/x-dosexec', 'application/x-msdownload', 'application/octet-stream'}),
    '.mp4':  frozenset({'video/mp4'}),
    '.mp3':  frozenset({'audio/mpeg'}),
    '.docx': frozenset({'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/zip'}),
    '.xlsx': frozenset({'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/zip'}),
    '.pptx': frozenset({'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'application/zip'}),
    '.docm': frozenset({'application/vnd.ms-word.document.macroEnabled.12', 'application/zip'}),
    '.xlsm': frozenset({'application/vnd.ms-excel.sheet.macroEnabled.12', 'application/zip'}),
}


class FeatureExtractor:
    """
    Transforms file/email events into structured metadata for LLM analysis.

    Callers:
      - gate_keeper.py (Gate 2, Downloads staging zone)
      - daemon.py (Desktop direct pipeline)

    extract(event) accepts a dict from file_watcher or email_scanner.
    Returns a flat feature dict. Never stores or forwards file contents.
    """

    def __init__(
        self,
        whois_timeout: int = 8,
        entropy_threshold: float = 7.2,
        entropy_sample_bytes: int = 1_048_576,  # 1 MB max read for entropy
    ) -> None:
        self._whois_timeout = whois_timeout
        self._entropy_threshold = entropy_threshold
        self._entropy_sample_bytes = entropy_sample_bytes
        # in-memory WHOIS TTL cache: domain -> (monotonic_ts, result_or_None)
        self._whois_cache: dict[str, tuple[float, dict | None]] = {}
        self._whois_cache_ttl: float = 86400.0  # 24 hours

        # B2 lookalike detection data — loaded once, used per-email
        _data_dir = Path(__file__).parent.parent.parent / "data"
        try:
            self._brands: list[dict] = json.loads(
                (_data_dir / "brands.json").read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("brands.json unavailable (%s) — lookalike checks disabled", exc)
            self._brands = []
        try:
            self._confusables: dict[str, str] = json.loads(
                (_data_dir / "confusables.json").read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("confusables.json unavailable (%s) — using empty confusable map", exc)
            self._confusables = {}

    def extract(self, event: dict) -> dict:
        """Dispatch to file or email extractor based on event source."""
        source = event.get("source", "")
        try:
            if source == "file_watcher":
                return self._extract_file(event)
            elif source == "email_scanner":
                return self._extract_email(event)
            else:
                log.warning("FeatureExtractor: unknown event source '%s'", source)
                return {"source": source, "error": "unknown_source"}
        except Exception:
            log.exception("FeatureExtractor: unhandled error (source=%s)", source)
            return {"source": source, "error": "extraction_failed"}

    # ------------------------------------------------------------------
    # FILE extraction
    # ------------------------------------------------------------------

    def _extract_file(self, event: dict) -> dict:
        path = Path(event["path"])
        ext = path.suffix.lower()
        features: dict[str, Any] = {
            "file_name": path.name,
            "file_path": str(path),
            "extension": ext,
        }

        if not path.exists():
            log.warning("File no longer exists at extraction time: %s", path)
            features["error"] = "file_not_found"
            return features

        # Size
        try:
            features["file_size_bytes"] = path.stat().st_size
        except OSError as e:
            log.warning("stat() failed for %s: %s", path.name, e)
            features["file_size_bytes"] = None

        # SHA-256 (needed for VirusTotal lookup in Gate 1.5) + MD5
        sha256, md5 = self._hash_file(path)
        features["sha256"] = sha256
        features["md5"] = md5

        # Read 4 KB header for magic operations
        try:
            with path.open("rb") as f:
                header = f.read(4096)
        except OSError as e:
            log.warning("Cannot read header of %s: %s", path.name, e)
            header = b""

        features["magic_bytes_hex"] = header[:4].hex() if header else None
        features["magic_bytes_desc"] = _identify_magic_bytes(header[:4])

        # python-magic for authoritative MIME + human description
        mime_type, magic_desc = _magic_identify(path)
        features["mime_type"] = mime_type
        features["magic_description"] = magic_desc

        # Extension vs real MIME mismatch — masquerading signal
        features["extension_mime_mismatch"] = _is_mime_mismatch(ext, mime_type)

        # Shannon entropy — high entropy suggests packed/encrypted payload
        entropy = self._compute_entropy(path)
        features["entropy"] = round(entropy, 4) if entropy is not None else None
        features["entropy_is_high"] = (
            entropy is not None and entropy > self._entropy_threshold
        )

        # Zone.Identifier ADS — set by browsers to record download origin
        zone = _read_zone_identifier(path)
        features["zone_identifier"] = zone
        origin_url = zone.get("HostUrl") if zone else None
        origin_domain = _extract_domain(origin_url)
        features["origin_url"] = origin_url
        features["origin_domain"] = origin_domain

        # Gate 3 category label for LLM context
        features["gate3_category"] = _GATE3_CATEGORY_MAP.get(ext)
        features["requires_gate3"] = ext in GATE3_EXTENSIONS
        features["never_execute_natively"] = ext in NEVER_EXECUTE_NATIVELY

        # PE metadata — for any file with MZ header, not just .exe extension
        is_pe = (header[:2] == b'\x4d\x5a') or (ext in {'.exe', '.dll', '.scr', '.com', '.pif', '.msi'})
        features["pe_info"] = self._extract_pe(path) if is_pe else None

        # Shortcut target analysis
        features["lnk_target"] = _extract_lnk_target(path) if ext == '.lnk' else None
        features["url_target"] = _extract_url_target(path) if ext == '.url' else None

        # Office macro detection (OOXML zip-based + OLE fallback)
        is_office_macro_ext = ext in {'.docm', '.xlsm', '.pptm', '.xll', '.iqy', '.slk'}
        features["has_macros"] = self._check_office_macros(path) if is_office_macro_ext else None

        # WHOIS on download origin domain (if known from Zone.Identifier)
        features["whois"] = self._cached_whois(origin_domain) if origin_domain else None

        return features

    # ------------------------------------------------------------------
    # EMAIL extraction
    # ------------------------------------------------------------------

    def _extract_email(self, event: dict) -> dict:
        """Enrich email_scanner metadata with WHOIS, DNS MX, and B1/B2 link analysis."""
        metadata: dict = dict(event.get("metadata", {}))
        features: dict[str, Any] = dict(metadata)

        from_domain: str | None = metadata.get("from_domain")
        reply_to_domain: str | None = metadata.get("reply_to_domain")
        reply_to_mismatch: bool = metadata.get("reply_to_mismatch", False)

        # WHOIS on sender domain — age < 30 days is a red flag
        features["whois_from"] = self._cached_whois(from_domain) if from_domain else None

        # WHOIS on reply-to only if it differs from sender (avoids unnecessary queries)
        features["whois_reply_to"] = (
            self._cached_whois(reply_to_domain)
            if (reply_to_mismatch and reply_to_domain)
            else None
        )

        # MX record check — domain with no MX records can't legitimately send email
        features["mx_valid"] = _check_mx(from_domain) if from_domain else None

        # B3: DKIM alignment — dkim=pass authenticates the signing domain, not From:
        # Misalignment (d=evil.com, From: @paypal.com) passes DKIM but is a spoof.
        dkim_val: str = metadata.get("dkim", "none")
        dkim_d: str = metadata.get("dkim_d", "") or ""
        if dkim_val == "pass" and dkim_d and from_domain:
            def _reg(d: str) -> str:
                parts = d.split(".")
                return parts[-2] if len(parts) >= 2 else d
            features["dkim_aligned"] = _reg(dkim_d.lower()) == _reg(from_domain.lower())
        else:
            features["dkim_aligned"] = False

        # B2 on sender and reply-to domains
        features["sender_lookalike"] = (
            _check_lookalike(from_domain, self._brands, self._confusables)[0]
            if from_domain and not _is_raw_ip(from_domain)
            else False
        )
        features["reply_to_lookalike"] = (
            _check_lookalike(reply_to_domain, self._brands, self._confusables)[0]
            if reply_to_mismatch and reply_to_domain and not _is_raw_ip(reply_to_domain)
            else False
        )

        # B1: iterate link domains — WHOIS + lookalike + raw-IP + shortener rollup
        links: list[dict] = metadata.get("links", [])
        link_domains: list[str] = []
        link_min_age: int | None = None
        any_link_lookalike = False
        any_link_raw_ip = False
        any_text_href_mismatch = False
        any_link_shortener = False   # ES-bug-1: was never initialised or populated
        whois_count = 0
        seen_domains: set[str] = set()

        for link in links:
            href: str = link.get("href", "")
            text: str = link.get("text", "")

            # Text-href mismatch: display text claims a different domain than href
            if not any_text_href_mismatch and _text_href_mismatch(href, text):
                any_text_href_mismatch = True

            domain = _extract_domain(href)
            if not domain or domain in seen_domains:
                continue
            seen_domains.add(domain)
            link_domains.append(domain)

            if _is_raw_ip(domain):
                any_link_raw_ip = True
                continue  # no WHOIS/lookalike/shortener on bare IPs

            # ES-bug-1: wire in the shortener check that was defined but never called
            if _is_shortener(domain):
                any_link_shortener = True

            # B2: lookalike check on each unique link domain
            if _check_lookalike(domain, self._brands, self._confusables)[0]:
                any_link_lookalike = True

            # WHOIS with hard per-message cap (MAX_LINK_WHOIS).
            # ES-bug-2: only count cache misses (actual network calls) against the cap;
            # a cache hit is free and must not burn a rate slot.
            if whois_count < MAX_LINK_WHOIS:
                now = time.monotonic()
                is_cached = (
                    domain in self._whois_cache
                    and now - self._whois_cache[domain][0] < self._whois_cache_ttl
                )
                result = self._cached_whois(domain)
                if not is_cached:
                    whois_count += 1
                if result and result.get("domain_age_days") is not None:
                    age: int = result["domain_age_days"]
                    if link_min_age is None or age < link_min_age:
                        link_min_age = age

        features["link_domains"] = link_domains
        features["link_min_domain_age_days"] = link_min_age
        features["any_link_lookalike"] = any_link_lookalike
        features["any_link_raw_ip"] = any_link_raw_ip
        features["any_text_href_mismatch"] = any_text_href_mismatch
        features["any_link_shortener"] = any_link_shortener

        return features

    # ------------------------------------------------------------------
    # Hashing
    # ------------------------------------------------------------------

    def _hash_file(self, path: Path) -> tuple[str, str]:
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        try:
            with path.open("rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha256.update(chunk)
                    md5.update(chunk)
            return sha256.hexdigest(), md5.hexdigest()
        except OSError as e:
            log.warning("Hash failed for %s: %s", path.name, e)
            return "", ""

    # ------------------------------------------------------------------
    # Entropy
    # ------------------------------------------------------------------

    def _compute_entropy(self, path: Path) -> float | None:
        try:
            with path.open("rb") as f:
                data = f.read(self._entropy_sample_bytes)
            return _shannon_entropy(data)
        except OSError as e:
            log.warning("Entropy read failed for %s: %s", path.name, e)
            return None

    # ------------------------------------------------------------------
    # PE metadata
    # ------------------------------------------------------------------

    def _extract_pe(self, path: Path) -> dict | None:
        try:
            import pefile
        except ImportError:
            log.warning("pefile not installed — PE extraction skipped")
            return None
        try:
            pe = pefile.PE(str(path), fast_load=True)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY'],
            ])

            # Compile timestamp — epoch 0 or future timestamp is suspicious
            ts = pe.FILE_HEADER.TimeDateStamp
            compile_time: str | None = None
            if ts and ts > 0:
                try:
                    compile_time = datetime.utcfromtimestamp(ts).isoformat()
                except (OSError, OverflowError, ValueError):
                    compile_time = hex(ts)

            # DLL imports — unusual imports (e.g. ntdll only, no kernel32) are suspicious
            imports: list[str] = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT[:30]:
                    try:
                        imports.append(entry.dll.decode('utf-8', errors='replace'))
                    except Exception:
                        pass

            # Sections with per-section entropy (high section entropy = packed)
            sections: list[dict] = []
            for section in pe.sections:
                try:
                    name = section.Name.decode('utf-8', errors='replace').rstrip('\x00')
                    sections.append({
                        "name": name,
                        "virtual_size": section.Misc_VirtualSize,
                        "raw_size": section.SizeOfRawData,
                        "entropy": round(section.get_entropy(), 4),
                    })
                except Exception:
                    pass

            # Authenticode signature (SECURITY directory present = signed by publisher)
            is_signed = (
                hasattr(pe, 'DIRECTORY_ENTRY_SECURITY') and
                bool(pe.DIRECTORY_ENTRY_SECURITY)
            )

            machine_val = pe.FILE_HEADER.Machine
            machine_str = pefile.MACHINE_TYPE.get(machine_val, hex(machine_val))
            num_sections = len(pe.sections)
            pe.close()

            return {
                "machine_type": str(machine_str),
                "compile_timestamp": compile_time,
                "imports": imports,
                "sections": sections,
                "is_signed": is_signed,
                "num_sections": num_sections,
            }
        except Exception as e:
            log.warning("PE extraction failed for %s: %s", path.name, e)
            return None

    # ------------------------------------------------------------------
    # Office macro detection
    # ------------------------------------------------------------------

    def _check_office_macros(self, path: Path) -> bool | None:
        """
        True if macros detected, False if clean, None if undetermined.
        DOCM/XLSM/PPTM are ZIP-based OOXML; vbaProject.bin = macros present.
        Falls back to OLE signature check for pre-OOXML binary formats.
        """
        try:
            with zipfile.ZipFile(path, 'r') as zf:
                names = zf.namelist()
                return any(
                    'vbaProject.bin' in n or 'vbaData.xml' in n
                    for n in names
                )
        except zipfile.BadZipFile:
            # Might be OLE binary format (.xls, .doc) — check magic bytes
            try:
                with path.open("rb") as f:
                    sig = f.read(4)
                # D0 CF 11 E0 = OLE Compound Document — assume macros possible
                return sig == b'\xd0\xcf\x11\xe0' or None
            except OSError:
                return None
        except Exception as e:
            log.warning("Macro check failed for %s: %s", path.name, e)
            return None

    # ------------------------------------------------------------------
    # WHOIS with 24h TTL cache
    # ------------------------------------------------------------------

    def _cached_whois(self, domain: str | None) -> dict | None:
        """WHOIS lookup with 24h in-memory cache and configurable timeout."""
        if not domain:
            return None
        now = time.monotonic()
        if domain in self._whois_cache:
            cached_ts, result = self._whois_cache[domain]
            if now - cached_ts < self._whois_cache_ttl:
                log.debug("WHOIS cache hit: %s", domain)
                return result

        result = self._do_whois(domain)
        self._whois_cache[domain] = (now, result)
        return result

    def _do_whois(self, domain: str) -> dict | None:
        def _lookup() -> dict | None:
            try:
                import whois as python_whois
                w = python_whois.whois(domain)
                creation_date = w.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]

                age_days: int | None = None
                if creation_date:
                    if creation_date.tzinfo is None:
                        creation_date = creation_date.replace(tzinfo=timezone.utc)
                    age_days = (datetime.now(timezone.utc) - creation_date).days

                return {
                    "domain_age_days": age_days,
                    "registrar": str(w.registrar) if w.registrar else None,
                    "creation_date": creation_date.isoformat() if creation_date else None,
                    "is_new_domain": (age_days is not None and age_days < 30),
                }
            except Exception as e:
                log.debug("WHOIS failed for %s: %s", domain, e)
                return None

        # Audit fix: ThreadPoolExecutor's context manager joins the worker on
        # exit, so a hung WHOIS socket blocked the processor thread for the full
        # hang despite the timeout. A daemon thread + join(timeout) abandons
        # the lookup cleanly and never blocks daemon shutdown.
        result_box: dict[str, dict | None] = {}

        def _worker() -> None:
            result_box["result"] = _lookup()

        t = threading.Thread(target=_worker, daemon=True, name=f"whois-{domain}")
        t.start()
        t.join(timeout=self._whois_timeout)
        if t.is_alive():
            log.warning("WHOIS timeout (%ds) for %s — lookup abandoned", self._whois_timeout, domain)
            return None
        return result_box.get("result")


# ------------------------------------------------------------------
# Module-level pure functions
# ------------------------------------------------------------------

def _shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte. Range: 0.0 (all same) to 8.0 (random)."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _read_zone_identifier(path: Path) -> dict | None:
    """
    Read the Windows Zone.Identifier ADS browsers attach to downloaded files.
    Returns parsed key-value dict (ZoneId, HostUrl, ReferrerUrl) or None.
    This ADS is invisible in Explorer and requires the :ADS notation to read.
    """
    zone_path = str(path) + ":Zone.Identifier"
    try:
        with open(zone_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        result: dict[str, str] = {}
        for line in content.splitlines():
            if '=' in line:
                key, _, value = line.partition('=')
                key, value = key.strip(), value.strip()
                if key and value:
                    result[key] = value
        return result if result else None
    except (FileNotFoundError, PermissionError, OSError):
        return None


def _extract_domain(url: str | None) -> str | None:
    """Extract hostname from a URL string, stripping www. prefix."""
    if not url:
        return None
    try:
        host = urlparse(url).hostname
        if host:
            return host.removeprefix("www.")
    except Exception:
        pass
    return None


def _extract_lnk_target(path: Path) -> str | None:
    """
    Extract target path from a Windows .lnk shortcut via PowerShell COM.
    WScript.Shell is always available — no extra dependencies.
    """
    try:
        escaped = str(path).replace("'", "''")
        result = subprocess.run(
            [
                "powershell", "-NoProfile", "-NonInteractive", "-Command",
                f"(New-Object -COM WScript.Shell).CreateShortcut('{escaped}').TargetPath",
            ],
            capture_output=True, text=True, timeout=10,
        )
        target = result.stdout.strip()
        return target if target else None
    except Exception as e:
        log.warning("LNK target extraction failed for %s: %s", path.name, e)
        return None


def _extract_url_target(path: Path) -> str | None:
    """Extract URL from a Windows Internet Shortcut (.url) INI-style file."""
    try:
        for line in path.read_text(encoding='utf-8', errors='replace').splitlines():
            if line.startswith("URL="):
                return line[4:].strip()
    except OSError as e:
        log.warning("URL shortcut read failed for %s: %s", path.name, e)
    return None


def _magic_identify(path: Path) -> tuple[str | None, str | None]:
    """Return (mime_type, human_description) from python-magic. Both None on error."""
    try:
        import magic as _magic_lib
        mime = _magic_lib.Magic(mime=True).from_file(str(path))
        desc = _magic_lib.Magic(mime=False).from_file(str(path))
        return mime, desc
    except Exception as e:
        log.warning("python-magic failed for %s: %s", path, e)
        return None, None


def _identify_magic_bytes(header: bytes) -> str | None:
    """Quick first-4-byte check against known signatures."""
    for sig, name in _MAGIC_SIGS.items():
        if header[:len(sig)] == sig:
            return name
    return None


def _is_mime_mismatch(ext: str, mime_type: str | None) -> bool:
    """True if the file extension claims one type but magic bytes say another."""
    if not mime_type or not ext:
        return False
    expected = _EXT_EXPECTED_MIMES.get(ext)
    if expected is None:
        return False  # no known mapping for this extension
    return mime_type not in expected


def _check_mx(domain: str) -> bool:
    """Return True if the domain has at least one MX record (5s timeout)."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, 'MX', lifetime=5.0)
        return len(answers) > 0
    except Exception:
        return False


# ------------------------------------------------------------------
# B2 — Lookalike / homograph / punycode detection helpers
# ------------------------------------------------------------------

def _is_raw_ip(domain: str) -> bool:
    """Return True if domain is an IPv4 or IPv6 address literal."""
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def _is_shortener(domain: str) -> bool:
    """Return True if domain is a known URL-shortening service."""
    return domain in _KNOWN_SHORTENERS


def _levenshtein(a: str, b: str) -> int:
    """Levenshtein edit distance between two strings (O(min(|a|,|b|)) space)."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    row = list(range(len(b) + 1))
    for char_a in a:
        new_row = [row[0] + 1]
        for j, char_b in enumerate(b):
            new_row.append(min(row[j + 1] + 1, new_row[-1] + 1, row[j] + (char_a != char_b)))
        row = new_row
    return row[-1]


def _domain_skeleton(label: str, confusables: dict[str, str]) -> str:
    """Collapse visually-similar characters in a domain label to their canonical forms."""
    return "".join(confusables.get(c, c) for c in label.lower())


def _check_lookalike(
    domain: str,
    brands: list[dict],
    confusables: dict[str, str],
) -> tuple[bool, str | None]:
    """
    Return (True, brand_name) if domain is a lookalike of any known brand.

    Algorithm (RFC 5891 / Unicode confusables approach):
    1. Decode each xn-- label via IDNA (punycode).
    2. Map each character to its skeleton using the confusables table.
    3. Compute Levenshtein between the skeleton of the registrable-domain
       label and each brand name.  Distance ≤ 1 = lookalike.
    4. The real brand domain is always excluded from flagging.
    """
    labels = domain.lower().split(".")
    decoded_labels: list[str] = []
    for label in labels:
        if label.startswith("xn--"):
            try:
                decoded_labels.append(label.encode("ascii").decode("idna"))
            except (UnicodeError, UnicodeDecodeError):
                decoded_labels.append(label)
        else:
            decoded_labels.append(label)

    # Registrable domain = second-to-last label (e.g. "paypa1" in paypa1.com)
    reg_label = decoded_labels[-2] if len(decoded_labels) >= 2 else decoded_labels[0]
    skeleton = _domain_skeleton(reg_label, confusables)

    for brand in brands:
        brand_name: str = brand.get("name", "")
        brand_domain: str = brand.get("domain", "")
        # Skip the real brand domain — paypal.com must never flag as lookalike
        if domain == brand_domain or domain.endswith("." + brand_domain):
            continue
        if _levenshtein(skeleton, brand_name) <= 1:
            return True, brand_name

    return False, None


def _text_href_mismatch(href: str, text: str) -> bool:
    """
    Return True when link display text claims a different domain than the href.
    Only fires for compact text (no spaces) that looks like a domain.
    """
    if not text:
        return False
    text = text.strip()
    if " " in text or "." not in text:
        return False
    href_domain = _extract_domain(href)
    # Prepend scheme so urlparse treats it as a netloc, not a path
    text_domain = _extract_domain(text if "://" in text else f"https://{text}")
    if not href_domain or not text_domain:
        return False

    def _reg(d: str) -> str:
        parts = d.split(".")
        return parts[-2] if len(parts) >= 2 else d

    return _reg(href_domain) != _reg(text_domain)


# ------------------------------------------------------------------
# Standalone test
# ------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    import tempfile

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(levelname)s %(name)s: %(message)s",
    )

    extractor = FeatureExtractor()
    print("=== A.R.G.U.S. Feature Extractor Tests ===\n")

    # -----------------------------------------------------------
    # Test 1: Fake PE file (MZ header + random high-entropy bytes)
    # -----------------------------------------------------------
    print("Test 1: fake PE executable (high entropy)")
    import os
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
        # MZ header + pseudo-random payload to push entropy high
        tmp.write(b'\x4d\x5a\x90\x00')  # MZ header
        tmp.write(bytes(range(256)) * 32)  # patterned bytes, moderate entropy
        tmp_path = Path(tmp.name)

    try:
        event = {
            "source": "file_watcher",
            "path": str(tmp_path),
            "event_type": "created",
            "staged": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        features = extractor.extract(event)
        print(f"  file_name:           {features['file_name']}")
        print(f"  sha256:              {features['sha256'][:16]}...")
        print(f"  mime_type:           {features['mime_type']}")
        print(f"  magic_bytes_desc:    {features['magic_bytes_desc']}")
        print(f"  entropy:             {features['entropy']}")
        print(f"  entropy_is_high:     {features['entropy_is_high']}")
        print(f"  gate3_category:      {features['gate3_category']}")
        print(f"  never_execute_natively: {features['never_execute_natively']}")
        print(f"  pe_info:             {features['pe_info']}")
        print(f"  zone_identifier:     {features['zone_identifier']}")
        assert features["sha256"] != "", "SHA-256 must not be empty"
        assert features["gate3_category"] == "executable"
        assert features["never_execute_natively"] is True
        assert features["magic_bytes_desc"] is not None  # MZ detected
        print("  PASSED\n")
    finally:
        tmp_path.unlink(missing_ok=True)

    # -----------------------------------------------------------
    # Test 2: Fake DOCM file (OOXML zip with vbaProject.bin)
    # -----------------------------------------------------------
    print("Test 2: fake DOCM with macros (vbaProject.bin)")
    with tempfile.NamedTemporaryFile(suffix=".docm", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    try:
        with zipfile.ZipFile(str(tmp_path), 'w') as zf:
            zf.writestr("word/document.xml", "<w:document/>")
            zf.writestr("word/vbaProject.bin", b"\x00" * 64)  # fake macro blob
        event = {
            "source": "file_watcher",
            "path": str(tmp_path),
            "event_type": "created",
            "staged": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        features = extractor.extract(event)
        print(f"  file_name:     {features['file_name']}")
        print(f"  has_macros:    {features['has_macros']}")
        print(f"  gate3_category: {features['gate3_category']}")
        assert features["has_macros"] is True, "Macros must be detected"
        assert features["gate3_category"] == "office_macro"
        print("  PASSED\n")
    finally:
        tmp_path.unlink(missing_ok=True)

    # -----------------------------------------------------------
    # Test 3: Windows Internet Shortcut (.url)
    # -----------------------------------------------------------
    print("Test 3: .url shortcut target extraction")
    with tempfile.NamedTemporaryFile(suffix=".url", delete=False, mode='w') as tmp:
        tmp.write("[InternetShortcut]\nURL=https://evil-phish.ru/payload\n")
        tmp_path = Path(tmp.name)

    try:
        event = {
            "source": "file_watcher",
            "path": str(tmp_path),
            "event_type": "created",
            "staged": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        features = extractor.extract(event)
        print(f"  url_target:    {features['url_target']}")
        print(f"  gate3_category: {features['gate3_category']}")
        assert features["url_target"] == "https://evil-phish.ru/payload"
        assert features["gate3_category"] == "shortcut"
        print("  PASSED\n")
    finally:
        tmp_path.unlink(missing_ok=True)

    # -----------------------------------------------------------
    # Test 4: Email event enrichment (synthetic phishing email)
    # -----------------------------------------------------------
    print("Test 4: email enrichment (synthetic phishing event)")
    email_event = {
        "source": "email_scanner",
        "event_type": "new_email",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": "from=paypal.com | reply_to=evil.ru [MISMATCH]",
        "metadata": {
            "from_domain": "paypal.com",
            "reply_to_domain": "evil.ru",
            "reply_to_mismatch": True,
            "spf": "fail",
            "dkim": "fail",
            "dmarc": "fail",
            "subject": "[SENSITIVE — stripped before cloud inference]",
            "_sensitive_fields": ["subject"],
            "html_only": True,
            "has_external_links": True,
            "links": [{"href": "http://paypal-secure-update.evil.ru/login", "text": ""}],
            "has_attachments": False,
        },
    }
    features = extractor.extract(email_event)
    print(f"  from_domain:   {features['from_domain']}")
    print(f"  reply_to_mismatch: {features['reply_to_mismatch']}")
    print(f"  mx_valid:      {features['mx_valid']}")
    print(f"  whois_from:    {features['whois_from']}")
    print(f"  whois_reply_to: {features['whois_reply_to']}")
    print(f"  sender_lookalike:     {features['sender_lookalike']}")
    print(f"  any_link_lookalike:   {features['any_link_lookalike']}")
    print(f"  any_link_raw_ip:      {features['any_link_raw_ip']}")
    print(f"  any_text_href_mismatch: {features['any_text_href_mismatch']}")
    print(f"  link_domains:  {features['link_domains']}")
    assert features["from_domain"] == "paypal.com"
    assert features["mx_valid"] is not None  # DNS call made
    assert "whois_reply_to" in features  # populated when reply_to_mismatch=True
    # paypal.com is the real brand domain — must not flag as lookalike
    assert features["sender_lookalike"] is False, "paypal.com must not be flagged as lookalike"
    # B1 rollup fields must be present
    assert "link_domains" in features
    assert "link_min_domain_age_days" in features
    assert "any_link_lookalike" in features
    assert "any_link_raw_ip" in features
    assert "any_text_href_mismatch" in features
    print("  PASSED\n")

    # -----------------------------------------------------------
    # Test 5: Shannon entropy pure function
    # -----------------------------------------------------------
    print("Test 5: entropy edge cases")
    assert _shannon_entropy(b"") == 0.0
    assert _shannon_entropy(b"\x00" * 1000) == 0.0  # all same byte = zero entropy
    high = _shannon_entropy(bytes(range(256)) * 4)
    assert high > 7.9, f"Expected near-max entropy, got {high}"
    print(f"  empty: 0.0  all-zero: 0.0  uniform-256: {high:.4f}")
    print("  PASSED\n")

    # -----------------------------------------------------------
    # Test 6: Zone.Identifier (Windows only — may not be present)
    # -----------------------------------------------------------
    print("Test 6: Zone.Identifier ADS (skipped if no ADS support)")
    # We can't reliably create an ADS in a temp file in all environments,
    # so just verify the function returns None gracefully on a normal file.
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        result = _read_zone_identifier(tmp_path)
        print(f"  result (expect None on file without ADS): {result}")
        assert result is None
        print("  PASSED\n")
    finally:
        tmp_path.unlink(missing_ok=True)

    # -----------------------------------------------------------
    # Test 7: B1 link domain analysis + B2 lookalike/raw-IP/mismatch
    # -----------------------------------------------------------
    print("Test 7: B1/B2 — lookalike domain, raw IP, shortener text-href mismatch")

    # 7a-B3: DKIM alignment checks
    b3_base = {
        "source": "email_scanner", "event_type": "new_email",
        "metadata": {
            "from_domain": "paypal.com",
            "reply_to_domain": "paypal.com", "reply_to_mismatch": False,
            "has_external_links": False, "links": [], "has_attachments": False,
            "html_only": False,
        },
    }
    # dkim=pass, d matches from_domain → aligned
    b3_aligned = dict(b3_base); b3_aligned["metadata"] = dict(b3_base["metadata"])
    b3_aligned["metadata"].update({"dkim": "pass", "dkim_d": "paypal.com", "spf": "pass", "dmarc": "pass"})
    assert extractor.extract(b3_aligned)["dkim_aligned"] is True, "B3: aligned must be True"
    print("  7a-B3: dkim=pass d=paypal.com From @paypal.com → aligned=True  PASSED")

    # dkim=pass, d=evil.com, From @paypal.com → NOT aligned
    b3_misaligned = dict(b3_base); b3_misaligned["metadata"] = dict(b3_base["metadata"])
    b3_misaligned["metadata"].update({"dkim": "pass", "dkim_d": "evil.com", "spf": "fail", "dmarc": "fail"})
    assert extractor.extract(b3_misaligned)["dkim_aligned"] is False, "B3: misaligned must be False"
    print("  7a-B3: dkim=pass d=evil.com From @paypal.com → aligned=False  PASSED")

    # dkim=none → always False regardless of dkim_d
    b3_none = dict(b3_base); b3_none["metadata"] = dict(b3_base["metadata"])
    b3_none["metadata"].update({"dkim": "none", "dkim_d": "", "spf": "none", "dmarc": "none"})
    assert extractor.extract(b3_none)["dkim_aligned"] is False, "B3: dkim=none must give False"
    print("  7a-B3: dkim=none → aligned=False  PASSED")

    # 7a: paypa1.com typosquat (1→l confusable) detected as lookalike
    is_la, brand = _check_lookalike("paypa1.com", extractor._brands, extractor._confusables)
    assert is_la, "paypa1.com must be detected as paypal lookalike"
    assert brand == "paypal", f"Expected lookalike_of='paypal', got {brand!r}"
    print(f"  7a: paypa1.com → lookalike_of={brand!r}  PASSED")

    # 7b: paypal.com itself must NOT be flagged
    is_la_real, _ = _check_lookalike("paypal.com", extractor._brands, extractor._confusables)
    assert not is_la_real, "paypal.com must not be flagged as a lookalike of itself"
    print("  7b: paypal.com → no flag  PASSED")

    # 7c: raw IP detection
    assert _is_raw_ip("203.0.113.42") is True
    assert _is_raw_ip("evil.ru") is False
    print("  7c: raw IP detection  PASSED")

    # 7d: text-href mismatch (text="paypal.com", href="http://bit.ly/abc")
    assert _text_href_mismatch("http://bit.ly/abc123", "paypal.com") is True
    assert _text_href_mismatch("http://paypal.com/signin", "paypal.com") is False
    assert _text_href_mismatch("http://evil.ru/login", "") is False  # no text
    print("  7d: text-href mismatch  PASSED")

    # 7e: full pipeline — phishing email with lookalike sender + raw IP link
    b1_event = {
        "source": "email_scanner",
        "event_type": "new_email",
        "metadata": {
            "from_domain": "paypa1.com",
            "reply_to_domain": "paypa1.com",
            "reply_to_mismatch": False,
            "spf": "pass", "dkim": "pass", "dkim_d": "paypa1.com", "dmarc": "pass",
            "auth_results_unverified": False,
            "has_external_links": True,
            "links": [
                {"href": "http://paypa1.com/login", "text": "Click here"},
                {"href": "http://203.0.113.42/steal", "text": ""},
                {"href": "http://bit.ly/abc123", "text": "paypal.com"},
            ],
            "has_attachments": False,
            "html_only": True,
        },
    }
    b1_features = extractor.extract(b1_event)
    assert b1_features["sender_lookalike"] is True, "paypa1.com sender must flag"
    assert b1_features["any_link_lookalike"] is True, "paypa1.com link must flag"
    assert b1_features["any_link_raw_ip"] is True, "raw IP link must flag"
    assert b1_features["any_text_href_mismatch"] is True, "bit.ly/paypal.com mismatch must flag"
    assert len(b1_features["link_domains"]) == 3
    print("  7e: full B1 pipeline  PASSED")

    print("  PASSED\n")

    print("=== All tests passed ===")
