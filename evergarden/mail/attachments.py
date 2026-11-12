from __future__ import annotations

import io
import re
import zipfile

MAX_DOWNLOAD_BYTES = 5 * 1024 * 1024
MAX_ZIP_ENTRIES = 1_000
MAX_ZIP_UNCOMPRESSED_BYTES = 50 * 1024 * 1024
MAX_ZIP_RATIO = 100

ALLOWED_MIME_TYPES = frozenset(
    {
        "application/json",
        "application/pdf",
        "application/rtf",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "image/gif",
        "image/heic",
        "image/jpeg",
        "image/png",
        "image/webp",
        "text/calendar",
        "text/csv",
        "text/plain",
    }
)
ZIP_MIME_TYPES = frozenset(
    {
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    }
)
FORBIDDEN_EXTENSIONS = frozenset(
    {
        ".app",
        ".bat",
        ".cmd",
        ".com",
        ".docm",
        ".exe",
        ".hta",
        ".html",
        ".htm",
        ".jar",
        ".js",
        ".jse",
        ".lnk",
        ".mjs",
        ".msi",
        ".pptm",
        ".ps1",
        ".scr",
        ".sh",
        ".svg",
        ".vbe",
        ".vbs",
        ".xlsm",
    }
)
EXECUTABLE_MAGIC = (
    b"MZ",
    b"\x7fELF",
    b"\xcf\xfa\xed\xfe",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xfe\xed\xfa\xce",
)


class AttachmentPolicyError(ValueError):
    pass


def safe_filename(value: str) -> str:
    normalized = value.replace("\\", "/").rsplit("/", 1)[-1]
    normalized = "".join(
        character for character in normalized if character >= " " and character != "\x7f"
    )
    normalized = normalized.strip().strip(".")
    return normalized[:255] or "attachment"


def _extension(filename: str) -> str:
    match = re.search(r"(\.[A-Za-z0-9]+)$", filename)
    return match.group(1).lower() if match else ""


def _validate_zip(content: bytes) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_ZIP_ENTRIES:
                raise AttachmentPolicyError("attachment archive has too many entries")
            total_compressed = sum(max(1, item.compress_size) for item in entries)
            total_uncompressed = sum(item.file_size for item in entries)
            if total_uncompressed > MAX_ZIP_UNCOMPRESSED_BYTES:
                raise AttachmentPolicyError("attachment archive expands beyond the safety limit")
            if total_uncompressed > total_compressed * MAX_ZIP_RATIO:
                raise AttachmentPolicyError("attachment archive compression ratio is unsafe")
            names = {item.filename.lower().replace("\\", "/") for item in entries}
            if any(
                name.endswith("vbaproject.bin") or name.endswith(".js") or name.endswith(".vbs")
                for name in names
            ):
                raise AttachmentPolicyError("active or macro content is forbidden")
    except zipfile.BadZipFile as exc:
        raise AttachmentPolicyError("office attachment container is malformed") from exc


def validate_download(
    *, filename: str, mimetype: str, content: bytes, requested_max_bytes: int
) -> tuple[str, str]:
    bounded_limit = max(1, min(int(requested_max_bytes), MAX_DOWNLOAD_BYTES))
    if len(content) > bounded_limit:
        raise AttachmentPolicyError("attachment exceeds the requested download limit")
    clean_name = safe_filename(filename)
    media_type = mimetype.lower().split(";", 1)[0].strip()
    if media_type not in ALLOWED_MIME_TYPES:
        raise AttachmentPolicyError("attachment MIME type is not allowlisted")
    if _extension(clean_name) in FORBIDDEN_EXTENSIONS:
        raise AttachmentPolicyError("active attachment type is forbidden")
    if content.startswith(EXECUTABLE_MAGIC) or content.startswith(b"#!"):
        raise AttachmentPolicyError("executable attachment content is forbidden")
    if media_type == "application/pdf" and not content.startswith(b"%PDF-"):
        raise AttachmentPolicyError("attachment content does not match its PDF type")
    if media_type == "image/png" and not content.startswith(b"\x89PNG\r\n\x1a\n"):
        raise AttachmentPolicyError("attachment content does not match its PNG type")
    if media_type == "image/jpeg" and not content.startswith(b"\xff\xd8\xff"):
        raise AttachmentPolicyError("attachment content does not match its JPEG type")
    if media_type in ZIP_MIME_TYPES:
        _validate_zip(content)
    if media_type.startswith("text/") and b"\x00" in content:
        raise AttachmentPolicyError("text attachment contains binary data")
    return clean_name, media_type
