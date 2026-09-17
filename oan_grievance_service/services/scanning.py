# Copyright (c) 2026, COSS - Centre for Open Societal Systems and contributors
# For license information, please see license.txt

"""Attachment scanning and validation.

WHY THIS EXISTS
---------------
A grievance portal accepts arbitrary files from the public internet and then
asks government staff to open them. Without a scanner in front of that, the
system is a malware delivery channel with an official letterhead.

THREE CHECKS, IN ORDER
----------------------
1. **Type, from the content.** Frappe's own File doctype derives `content_type`
   from `mimetypes.guess_type(file_name)` (file.py:735), which reads only the
   extension. A payload renamed from `.exe` to `.jpg` is reported by Frappe as
   `image/jpeg`. Demonstrated:

       disguised.jpg   sniffed=application/x-msdownload   by-extension=image/jpeg

   So the type is read from the leading bytes instead, and the extension is
   checked only for agreement with what the bytes say.

2. **Location metadata, stripped.** A phone photo carries GPS coordinates in its
   EXIF block. FSD 9.2 lets a submitter ask for anonymity -- and a geotagged
   photograph of their own plot defeats that completely, whatever the database
   says about their name. Coordinates are removed before the file is stored.

3. **Malware, by an external scanner.** ClamAV over its daemon socket.

WHY CLAMAV RATHER THAN A CLOUD SCANNER
--------------------------------------
The alternative is a hosted API -- VirusTotal or a cloud provider's scanner --
which means uploading the file itself to a third party outside Ethiopia.
Grievance attachments are evidence submitted by farmers: receipts with names on
them, photographs of their land, voice recordings of their complaint. Sending
that abroad to decide whether it is a virus trades one risk for a worse one,
and it is not a trade a public grievance system gets to make quietly.

ClamAV is self-hosted, its signature database updates over the network without
the files leaving, and it runs as a sidecar container alongside MariaDB and
Redis. Configure it with `grievance_clamav_host` and `grievance_clamav_port` in
site config.

FAIL CLOSED
-----------
With no scanner reachable, a file is marked `Failed`, never `Clean`. Nothing is
served to an officer until something has actually looked at it. An outage makes
attachments unavailable; it does not make them trusted.
"""

import hashlib
import socket

import frappe
from frappe import _
from frappe.utils import now_datetime

from oan_grievance_service.grievance_management.doctype.grievance_attachment.grievance_attachment import (
	ALLOWED_MIME_TYPES,
	EXTENSION_FOR_MIME,
	MAX_SIZE_BYTES,
)

CLAMAV_DEFAULT_PORT = 3310
CLAMAV_TIMEOUT_SECONDS = 30
CLAMAV_CHUNK = 8192

SCAN_PENDING = "Pending"
SCAN_CLEAN = "Clean"
SCAN_INFECTED = "Infected"
SCAN_FAILED = "Failed"

# EXIF tag 34853 is the GPS block. Pillow exposes it by number rather than name.
EXIF_GPS_TAG = 34853


# ---------------------------------------------------------------------------
# 1. Type, read from the content
# ---------------------------------------------------------------------------


def sniff_mime(content: bytes) -> str | None:
	"""The MIME type the leading bytes actually describe, or None if unrecognised.

	`filetype` ships with Frappe and reads magic numbers in pure Python, so this
	needs no subprocess and no libmagic build.
	"""
	import filetype

	kind = filetype.guess(content)
	return kind.mime if kind else None


def sha256_of(content: bytes) -> str:
	"""A tamper-evident digest of the stored bytes.

	Core's File.content_hash is MD5 and is marked usedforsecurity=False -- it exists
	to spot a duplicate upload, not to prove a file is the one that was submitted.
	Grievance evidence may later be what a decision rested on, so it gets a real
	digest, taken after the EXIF strip so it matches what is actually on disk.
	"""
	return hashlib.sha256(content).hexdigest()


def validate_upload(file_name: str, content: bytes) -> str:
	"""Check one upload against the evidence policy. Returns the sniffed type.

	Raises rather than returning a verdict, because every caller here wants the
	upload refused rather than recorded as suspect.
	"""
	size = len(content)
	if size > MAX_SIZE_BYTES:
		frappe.throw(
			_("{0} is {1} MB. The limit is {2} MB.").format(
				frappe.bold(file_name),
				round(size / (1024 * 1024), 1),
				MAX_SIZE_BYTES // (1024 * 1024),
			),
			title=_("File Too Large"),
		)

	mime = sniff_mime(content)
	if mime is None:
		frappe.throw(
			_("{0} is not a file type we recognise. Allowed: JPG, PNG, PDF and MP3.").format(
				frappe.bold(file_name)
			),
			title=_("Unrecognised File"),
		)

	if mime not in ALLOWED_MIME_TYPES:
		frappe.throw(
			_("{0} files are not accepted. Allowed: JPG, PNG, PDF and MP3.").format(mime),
			title=_("Unsupported File Type"),
		)

	lowered = (file_name or "").lower()
	if lowered and not lowered.endswith(EXTENSION_FOR_MIME[mime]):
		frappe.throw(
			_("{0} does not match its contents, which are {1}.").format(frappe.bold(file_name), mime),
			title=_("Extension Does Not Match Content"),
		)

	return mime


# ---------------------------------------------------------------------------
# 2. Location metadata, stripped
# ---------------------------------------------------------------------------


def strip_location_metadata(content: bytes, mime: str) -> bytes:
	"""Remove EXIF from an image, GPS coordinates included.

	Only images carry this. A submitter who asked for anonymity and then attached
	a photograph of their own field has told anyone with the file exactly where
	they are, and no amount of masking in the database undoes that.

	Re-encoding drops every EXIF block rather than only the GPS tag, which is the
	safer default: camera serial numbers and owner names live there too.
	"""
	if mime not in ("image/jpeg", "image/png"):
		return content

	import io

	from PIL import Image

	try:
		source = Image.open(io.BytesIO(content))
		clean = Image.new(source.mode, source.size)
		# paste() copies in C. putdata(list(getdata())) built a Python list of every
		# pixel first, so a 12-megapixel photo -- well inside the 10 MB ceiling --
		# cost hundreds of megabytes before a single byte was written.
		clean.paste(source)

		out = io.BytesIO()
		clean.save(out, format=source.format)
		return out.getvalue()
	except Exception:
		# A file Pillow cannot parse is not one we should be re-encoding. Leave it
		# for the malware scan to judge rather than silently passing it through
		# half-processed.
		frappe.log_error(title="Attachment metadata strip failed")
		return content


def has_location_metadata(content: bytes) -> bool:
	"""Whether an image still carries GPS coordinates. Used by the tests."""
	import io

	from PIL import Image

	try:
		exif = Image.open(io.BytesIO(content)).getexif()
	except Exception:
		return False

	return EXIF_GPS_TAG in exif


# ---------------------------------------------------------------------------
# 3. Malware, by ClamAV
# ---------------------------------------------------------------------------


def clamav_target() -> tuple[str, int] | None:
	host = frappe.conf.get("grievance_clamav_host")
	if not host:
		return None
	return host, int(frappe.conf.get("grievance_clamav_port") or CLAMAV_DEFAULT_PORT)


def scan_bytes(content: bytes) -> tuple[str, str]:
	"""Hand the content to clamd and return (status, detail).

	Uses INSTREAM so nothing is written to a path the scanner has to share. The
	wire format is clamd's own: a length-prefixed chunk sequence terminated by a
	zero length.
	"""
	target = clamav_target()
	if not target:
		return SCAN_FAILED, "No scanner configured (grievance_clamav_host is unset)."

	host, port = target
	try:
		with socket.create_connection((host, port), timeout=CLAMAV_TIMEOUT_SECONDS) as sock:
			sock.sendall(b"zINSTREAM\0")
			for start in range(0, len(content), CLAMAV_CHUNK):
				chunk = content[start : start + CLAMAV_CHUNK]
				sock.sendall(len(chunk).to_bytes(4, "big") + chunk)
			sock.sendall((0).to_bytes(4, "big"))

			reply = sock.recv(4096).decode("utf-8", "replace").strip()
	except OSError as exc:
		return SCAN_FAILED, f"Scanner unreachable: {exc}"

	if reply.endswith("OK"):
		return SCAN_CLEAN, reply
	if "FOUND" in reply:
		return SCAN_INFECTED, reply
	return SCAN_FAILED, reply or "Scanner returned nothing."


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def scan_attachment(name: str) -> str:
	"""Scan one Grievance Attachment and record the verdict.

	An infected file loses its object and keeps its row: the case still needs to
	show that something was submitted and what happened to it.
	"""
	attachment = frappe.get_doc("Grievance Attachment", name)
	content = _read_object(attachment.file_url)
	if content is None:
		_record(attachment, SCAN_FAILED, "File object could not be read.")
		return SCAN_FAILED

	status, detail = scan_bytes(content)
	if status == SCAN_INFECTED:
		_discard_object(attachment.file_url)

	_record(attachment, status, detail)
	return status


def scan_pending(limit: int = 50) -> int:
	"""Drain the scan queue. Wired to the scheduler."""
	pending = frappe.get_all(
		"Grievance Attachment",
		filters={"scan_status": SCAN_PENDING},
		pluck="name",
		limit_page_length=limit,
		order_by="creation",
	)
	for name in pending:
		try:
			scan_attachment(name)
		except Exception:
			frappe.log_error(title=f"Attachment scan failed: {name}")
	return len(pending)


def _record(attachment, status: str, detail: str) -> None:
	attachment.db_set(
		{"scan_status": status, "scan_detail": detail[:500], "scanned_at": now_datetime()},
		update_modified=False,
	)


def _read_object(file_url: str) -> bytes | None:
	if not file_url:
		return None
	name = frappe.db.get_value("File", {"file_url": file_url}, "name")
	if not name:
		return None
	try:
		return frappe.get_doc("File", name).get_content()
	except Exception:
		return None


def _discard_object(file_url: str) -> None:
	"""Delete the stored object, keeping the attachment row and its trail."""
	name = frappe.db.get_value("File", {"file_url": file_url}, "name")
	if name:
		frappe.delete_doc("File", name, force=True, ignore_permissions=True)
