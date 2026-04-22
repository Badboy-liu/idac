#!/usr/bin/env python3
"""IDA Pro 9.x license keygen + binary patcher.

Generates a signed ``idapro.hexlic`` and patches IDA's RSA modulus in
``libida``/``libida32`` (.dll/.dylib/.so) so the forged license validates.
Functional mirror of ``src/main.cpp``.

Crack mechanism: IDA verifies signatures with a 1024-bit RSA modulus embedded
in its binary. Flipping one nibble of that modulus (``5C`` -> ``CB`` at byte 3)
turns it into a different N whose private exponent we know, so we can sign any
license payload and have IDA accept it.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import platform
import sys
from collections.abc import Callable, Iterator
from pathlib import Path

# ---------------------------------------------------------------------------
# Crypto constants
# ---------------------------------------------------------------------------

# Hex strings represent the bignum bytes in little-endian (IDA's wire format).
PUB_MODULUS_HEXRAYS = (
    "edfd425cf978546e8911225884436c57140525650bcf6ebfe80edbc5fb1de68f"
    "4c66c29cb22eb668788afcb0abbb718044584b810f8970cddf227385f75d5ddd"
    "d91d4f18937a08aa83b28c49d12dc92e7505bb38809e91bd0fbd2f2e6ab1d2e3"
    "3c0c55d5bddd478ee8bf845fcef3c82b9d2929ecb71f4d1b3db96e3a8e7aaf93"
)
PUB_MODULUS_PATCHED = (
    "edfd42cbf978546e8911225884436c57140525650bcf6ebfe80edbc5fb1de68f"
    "4c66c29cb22eb668788afcb0abbb718044584b810f8970cddf227385f75d5ddd"
    "d91d4f18937a08aa83b28c49d12dc92e7505bb38809e91bd0fbd2f2e6ab1d2e3"
    "3c0c55d5bddd478ee8bf845fcef3c82b9d2929ecb71f4d1b3db96e3a8e7aaf93"
)
PRIVATE_KEY = (
    "77c86abbb7f3bb134436797b68ff47beb1a5457816608dbfb72641814dd464dd"
    "640d711d5732d3017a1c4e63d835822f00a4eab619a2c4791cf33f9f57f9c2ae"
    "4d9eed9981e79ac9b8f8a411f68f25b9f0c05d04d11e22a3a0d8d4672b56a61f"
    "1532282ff4e4e74759e832b70e98b9d102d07e9fb9ba8d15810b144970029874"
)

# 6-byte signature at the start of the modulus blob in IDA's binary.
ORIGINAL_MAGIC = bytes.fromhex("EDFD425CF978")
PATCHED_MAGIC = bytes.fromhex("EDFD42CBF978")

# ---------------------------------------------------------------------------
# License template
# ---------------------------------------------------------------------------

DECOMPILER_ADDONS = (
    "HEXX86", "HEXX64",
    "HEXARM", "HEXARM64",
    "HEXMIPS", "HEXMIPS64",
    "HEXPPC", "HEXPPC64",
    "HEXRV64",
    "HEXARC", "HEXARC64",
)

LICENSE_TEMPLATE: dict = {
    "header": {"version": 1},
    "payload": {
        "name": "HuanmengX",
        "email": "idapro9@example.com",
        "licenses": [
            {
                "id": "48-2137-ACAB-99",
                "edition_id": "ida-pro",
                "description": "license",
                "license_type": "named",
                "product": "IDA",
                "product_id": "IDAPRO",
                "product_version": "9.3",
                "seats": 1,
                "start_date": "2024-08-10 00:00:00",
                "end_date": "2083-12-31 23:59:59",
                "issued_on": "2024-08-10 00:00:00",
                "owner": "Creaked By HuanmengX@outlook.com",
                "add_ons": [],
                "features": [],
            }
        ],
    },
}

OUTPUT_FILENAME = "idapro.hexlic"

# ---------------------------------------------------------------------------
# JSON / addon helpers
# ---------------------------------------------------------------------------

def canonical_json(obj) -> str:
    """Bytes IDA hashes during signature verification (sorted keys, no spaces)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def add_every_decompiler(license_obj: dict) -> None:
    addons = license_obj["payload"]["licenses"][0]["add_ons"]
    parent_id = license_obj["payload"]["licenses"][0]["id"]
    for i, code in enumerate(DECOMPILER_ADDONS, start=1):
        addons.append({
            "id": f"48-1337-0000-{i:02}",
            "code": code,
            "owner": parent_id,
            "start_date": "2024-08-10 00:00:00",
            "end_date": "2083-12-31 23:59:59",
        })

# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------

def _le_hex_to_int(hex_str: str) -> int:
    return int.from_bytes(bytes.fromhex(hex_str), byteorder="little")


def _rsa_sign(message: bytes) -> bytes:
    """Textbook RSA: treat ``message`` as big-endian, sign, return little-endian."""
    n = _le_hex_to_int(PUB_MODULUS_PATCHED)
    d = _le_hex_to_int(PRIVATE_KEY)
    sig = pow(int.from_bytes(message, "big"), d, n)
    return sig.to_bytes((sig.bit_length() + 7) // 8, "little")


def sign_hexlic(payload: dict) -> str:
    """Produce the hex signature IDA's verifier expects.

    The signed block is exactly 128 bytes: ``0x42`` * 33 || SHA-256(canonical JSON).
    """
    canonical = canonical_json({"payload": payload})
    digest = hashlib.sha256(canonical.encode()).digest()

    block = bytearray(128)
    block[:33] = b"\x42" * 33
    block[33:33 + 32] = digest

    return _rsa_sign(bytes(block)).hex().upper()

# ---------------------------------------------------------------------------
# Binary patching
# ---------------------------------------------------------------------------

def patch(target: Path) -> bool:
    """Patch IDA's modulus in ``target``. Returns True if a write occurred."""
    if not target.is_file():
        print(f"  Skip: {target} - didn't find")
        return False

    data = target.read_bytes()

    if PATCHED_MAGIC in data:
        print(f"  Already: {target} - patched modulus present")
        return False

    if ORIGINAL_MAGIC not in data:
        print(f"  Skip: {target} - doesn't contain original modulus")
        return False

    target.write_bytes(data.replace(ORIGINAL_MAGIC, PATCHED_MAGIC))
    print(f"  OK: {target} - patched")
    return True

# ---------------------------------------------------------------------------
# Install discovery (mirrors find_ida_install_dirs in main.cpp)
# ---------------------------------------------------------------------------

LIB_NAMES_BY_PLATFORM: dict[str, tuple[str, ...]] = {
    "Windows": ("ida.dll", "ida32.dll"),
    "Darwin":  ("libida.dylib", "libida32.dylib"),
    "Linux":   ("libida.so", "libida32.so"),
}


def _normalize_install_dir(p: Path) -> Path:
    """Auto-append ``Contents/MacOS`` for ``.app`` bundles on macOS."""
    if sys.platform == "darwin" and p.suffix == ".app":
        return p / "Contents" / "MacOS"
    return p


def _walk_strings(obj) -> Iterator[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _walk_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_strings(v)


def _dirs_from_config(cfg_path: Path) -> Iterator[Path]:
    """Pull existing-directory paths out of an ``ida-config.json``-style file."""
    try:
        data = json.loads(cfg_path.read_bytes())
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return
    for s in _walk_strings(data):
        p = Path(s)
        if p.is_dir():
            yield p


def _scan_dir(root: Path, predicate: Callable[[str], bool]) -> Iterator[Path]:
    if not root.is_dir():
        return
    try:
        entries = list(root.iterdir())
    except (PermissionError, OSError):
        return
    for entry in entries:
        if entry.is_dir() and predicate(entry.name):
            yield entry


def find_ida_install_dirs() -> list[Path]:
    """Discover candidate IDA install directories, in priority order."""
    dirs: list[Path] = [Path(".")]

    if idadir := os.environ.get("IDADIR"):
        dirs.append(Path(idadir))

    sysname = platform.system()
    if sysname == "Windows":
        roots = [Path("C:/Program Files"), Path("C:/Program Files (x86)")]
        for var in ("ProgramFiles", "ProgramFiles(x86)"):
            if v := os.environ.get(var):
                roots.append(Path(v))
        for root in roots:
            dirs.extend(_scan_dir(root, lambda n: n.startswith("IDA")))
    elif sysname == "Darwin":
        dirs.extend(_scan_dir(
            Path("/Applications"),
            lambda n: n.startswith("IDA") and n.endswith(".app"),
        ))
    else:
        dirs.extend(_scan_dir(Path("/opt"), lambda n: n.lower().startswith("ida")))
        if home := os.environ.get("HOME"):
            dirs.extend(_scan_dir(Path(home), lambda n: n.lower().startswith("ida")))

    if home := os.environ.get("HOME"):
        dirs.extend(_dirs_from_config(Path(home) / ".idapro" / "ida-config.json"))
    if sysname == "Windows" and (appdata := os.environ.get("APPDATA")):
        dirs.extend(_dirs_from_config(
            Path(appdata) / "Hex-Rays" / "IDA Pro" / "ida-config.json"
        ))

    seen: set[str] = set()
    out: list[Path] = []
    for d in (_normalize_install_dir(p) for p in dirs):
        key = str(d)
        if key not in seen:
            seen.add(key)
            out.append(d)
    return out

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

IDADIR_HINT: dict[str, str] = {
    "Windows": r'  set IDADIR=C:\Program Files\IDA Professional 9.3',
    "Darwin":  r'  export IDADIR="/Applications/IDA Professional 9.3.app/Contents/MacOS"',
    "Linux":   r'  export IDADIR=/opt/idapro-9.3',
}


def _wait_for_user() -> None:
    if platform.system() == "Windows":
        os.system("pause")
        return
    try:
        input("Press Enter to exit...")
    except (EOFError, KeyboardInterrupt):
        pass


def main() -> int:
    sysname = platform.system()
    libnames = LIB_NAMES_BY_PLATFORM.get(sysname)
    if libnames is None:
        print(f"Unsupported platform: {sysname}", file=sys.stderr)
        return 1

    license_obj = copy.deepcopy(LICENSE_TEMPLATE)
    add_every_decompiler(license_obj)
    license_obj["signature"] = sign_hexlic(license_obj["payload"])
    Path(OUTPUT_FILENAME).write_bytes(canonical_json(license_obj).encode())
    print(f"Saved new license to {OUTPUT_FILENAME}")

    print("\nDiscovering IDA installs...")
    any_patched = False
    for install_dir in find_ida_install_dirs():
        for name in libnames:
            if patch(install_dir / name):
                any_patched = True

    if not any_patched:
        print(
            "\nNo IDA install with the original modulus was patched.\n"
            "If your install is in a non-standard location, set IDADIR and re-run, e.g.:\n"
            f"{IDADIR_HINT[sysname]}"
        )

    if sysname == "Darwin":
        print(
            '\nOn macOS, re-sign the app after patching, e.g.:\n'
            '  codesign --force --deep --sign - '
            '"/Applications/IDA Professional 9.3.app"'
        )

    _wait_for_user()
    return 0


if __name__ == "__main__":
    sys.exit(main())
