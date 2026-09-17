# Copyright (c) 2026, COSS - Centre for Open Societal Systems and Contributors
# See license.txt

"""The upload endpoint, end to end.

The scanning service already has its own tests for the three checks in isolation.
What these cover is that the endpoint actually applies them -- that a renamed
executable is refused at the door rather than merely refusable, and that a file
nobody has scanned yet cannot be downloaded.
"""

import io

import frappe
from frappe.tests.utils import FrappeTestCase

from oan_grievance_service.api.v1 import attachment
from oan_grievance_service.services import scanning, submission
from oan_grievance_service.tests.fixtures import a_grievance

WINDOWS_EXECUTABLE = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"


def _pdf() -> bytes:
	"""A structurally valid PDF.

	Not a handful of header bytes: core's File runs pdf_contains_js() over every
	PDF upload -- its own check for embedded JavaScript -- and that parses the
	whole document. A truncated fixture fails there rather than in anything this
	module does.
	"""
	from io import BytesIO

	from pypdf import PdfWriter

	writer = PdfWriter()
	writer.add_blank_page(width=72, height=72)
	out = BytesIO()
	writer.write(out)
	return out.getvalue()


def _jpeg(with_gps: bool = False) -> bytes:
	from PIL import Image

	image = Image.new("RGB", (8, 8), (120, 140, 110))
	out = io.BytesIO()
	if with_gps:
		exif = image.getexif()
		gps = exif.get_ifd(scanning.EXIF_GPS_TAG)
		gps[1] = "N"
		gps[2] = (9.0, 10.0, 0.0)
		gps[3] = "E"
		gps[4] = (38.0, 45.0, 0.0)
		image.save(out, format="JPEG", exif=exif)
	else:
		image.save(out, format="JPEG")
	return out.getvalue()


class _Upload:
	"""Stands in for the werkzeug FileStorage the endpoint reads off the request."""

	def __init__(self, filename, content):
		self.filename = filename
		self.stream = io.BytesIO(content)


class _Request:
	"""A minimal stand-in for the werkzeug request.

	`host` is here because saving a File reaches frappe.utils.get_url(), which asks
	the request for its host before resolving a storage path. Left falsy so that
	lookup falls through to the site config, as it does outside a web request.
	"""

	def __init__(self, upload):
		self.files = {"file": upload} if upload else {}
		self.path = "/api/method/test"
		self.host = None


class AttachmentAPITestCase(FrappeTestCase):
	def setUp(self):
		self.grievance = a_grievance()
		self._saved_request = getattr(frappe.local, "request", None)

	def tearDown(self):
		frappe.local.request = self._saved_request
		frappe.db.rollback()

	def _send(self, filename, content, **kwargs):
		frappe.local.request = _Request(_Upload(filename, content))
		return attachment.submit_document(grievance=self.grievance.name, **kwargs)


class TestUploadGate(AttachmentAPITestCase):
	def test_a_valid_image_is_accepted_and_queued(self):
		result = self._send("receipt.jpg", _jpeg())

		self.assertEqual(result["status"], "success")
		self.assertEqual(result["data"]["mime_type"], "image/jpeg")
		# Pending, not Clean: nothing has looked at it yet.
		self.assertEqual(result["data"]["scan_status"], "Pending")

	def test_a_pdf_is_accepted(self):
		result = self._send("evidence.pdf", _pdf())
		self.assertEqual(result["data"]["mime_type"], "application/pdf")

	def test_an_executable_renamed_to_jpg_is_refused(self):
		"""The extension says image; the bytes decide, and they say otherwise."""
		result = self._send("holiday.jpg", WINDOWS_EXECUTABLE)
		self.assertEqual(result["status"], "error")

	def test_an_oversized_file_is_refused(self):
		oversized = _jpeg() + b"\x00" * scanning.MAX_SIZE_BYTES
		result = self._send("huge.jpg", oversized)
		self.assertEqual(result["status"], "error")

	def test_an_empty_upload_is_refused(self):
		result = self._send("nothing.jpg", b"")
		self.assertEqual(result["status"], "error")

	def test_a_request_with_no_file_is_refused(self):
		frappe.local.request = _Request(None)
		result = attachment.submit_document(grievance=self.grievance.name)
		self.assertEqual(result["status"], "error")

	def test_an_upload_naming_neither_grievance_nor_draft_is_refused(self):
		frappe.local.request = _Request(_Upload("receipt.jpg", _jpeg()))
		result = attachment.submit_document()
		self.assertEqual(result["status"], "error")


class TestLocationMetadataIsStripped(AttachmentAPITestCase):
	def test_coordinates_do_not_survive_the_upload(self):
		"""FSD 9.2 anonymity would otherwise die in the EXIF block."""
		original = _jpeg(with_gps=True)
		self.assertTrue(scanning.has_location_metadata(original))

		result = self._send("field.jpg", original)
		name = result["data"]["attachment"]
		stored = frappe.get_doc("Grievance Attachment", name)

		file_name = frappe.db.get_value("File", {"file_url": stored.file_url}, "name")
		content = frappe.get_doc("File", file_name).get_content()
		self.assertFalse(scanning.has_location_metadata(content))

	def test_the_checksum_matches_what_was_actually_stored(self):
		"""Taken after the strip, so it describes the bytes on disk, not the upload."""
		result = self._send("field.jpg", _jpeg(with_gps=True))
		stored = frappe.get_doc("Grievance Attachment", result["data"]["attachment"])

		file_name = frappe.db.get_value("File", {"file_url": stored.file_url}, "name")
		content = frappe.get_doc("File", file_name).get_content()
		self.assertEqual(stored.checksum_sha256, scanning.sha256_of(content))


class TestDownloadIsGatedOnTheScan(AttachmentAPITestCase):
	def _uploaded(self):
		result = self._send("receipt.jpg", _jpeg())
		return result["data"]["attachment"]

	def test_a_pending_file_cannot_be_downloaded(self):
		result = attachment.download(attachment=self._uploaded())
		self.assertEqual(result["status"], "error")

	def test_a_clean_file_can_be(self):
		name = self._uploaded()
		frappe.db.set_value("Grievance Attachment", name, "scan_status", "Clean")

		result = attachment.download(attachment=name)
		self.assertEqual(result["status"], "success")
		self.assertTrue(result["data"]["file_url"])

	def test_an_infected_file_stays_withheld(self):
		name = self._uploaded()
		frappe.db.set_value("Grievance Attachment", name, "scan_status", "Infected")

		result = attachment.download(attachment=name)
		self.assertEqual(result["status"], "error")

	def test_a_failed_scan_withholds_too(self):
		"""Fail closed: an outage makes a file unavailable, not trusted."""
		name = self._uploaded()
		frappe.db.set_value("Grievance Attachment", name, "scan_status", "Failed")

		result = attachment.download(attachment=name)
		self.assertEqual(result["status"], "error")


class TestTheObjectIsNotReachableAroundTheGate(AttachmentAPITestCase):
	"""The download endpoint is not the only way to a private file.

	Core serves /private/files/<name> itself and decides permission by asking
	whatever the File is attached to. While these files hung off the Grievance,
	that question was "may you read the case" -- which an officer can -- so the
	scan verdict was never consulted and download() guarded a door beside an open
	window.
	"""

	def _uploaded(self):
		result = self._send("receipt.jpg", _jpeg())
		return result["data"]["attachment"]

	def _file_of(self, name):
		url = frappe.db.get_value("Grievance Attachment", name, "file_url")
		return frappe.get_doc("File", frappe.db.get_value("File", {"file_url": url}, "name"))

	def _as_officer(self):
		"""Ask the question as someone the check actually applies to.

		Administrator bypasses has_permission entirely, so asserting as Administrator
		would pass whether the gate existed or not -- it would test nothing.
		"""
		email = "attachment.officer@example.com"
		if frappe.db.exists("User", email):
			frappe.delete_doc("User", email, force=True, ignore_permissions=True)
		frappe.get_doc(
			{
				"doctype": "User",
				"email": email,
				"first_name": "Attachment Officer",
				"send_welcome_email": 0,
				"roles": [{"role": "Grievance Officer"}],
			}
		).insert(ignore_permissions=True)

		self.addCleanup(frappe.set_user, "Administrator")
		frappe.set_user(email)
		return email

	def test_the_file_hangs_off_the_attachment_not_the_case(self):
		name = self._uploaded()
		stored = self._file_of(name)

		self.assertEqual(stored.attached_to_doctype, "Grievance Attachment")
		self.assertEqual(stored.attached_to_name, name)

	def test_core_refuses_to_serve_a_file_that_has_not_been_scanned(self):
		name = self._uploaded()
		self._as_officer()
		self.assertFalse(frappe.has_permission("Grievance Attachment", "read", doc=name))

	def test_core_serves_it_once_the_scan_is_clean(self):
		name = self._uploaded()
		frappe.db.set_value("Grievance Attachment", name, "scan_status", "Clean")
		self._as_officer()

		self.assertTrue(frappe.has_permission("Grievance Attachment", "read", doc=name))

	def test_an_infected_file_stays_unreachable_by_the_direct_route(self):
		name = self._uploaded()
		frappe.db.set_value("Grievance Attachment", name, "scan_status", "Infected")
		self._as_officer()

		self.assertFalse(frappe.has_permission("Grievance Attachment", "read", doc=name))

	def test_no_url_is_handed_back_at_upload_time(self):
		"""Returning it was the other half of the leak: a client could hold the path
		before anything had looked at the bytes."""
		result = self._send("receipt.jpg", _jpeg())
		self.assertNotIn("file_url", result["data"])


class TestListing(AttachmentAPITestCase):
	def test_every_attachment_is_listed_with_its_verdict(self):
		self._send("one.jpg", _jpeg())
		self._send("two.pdf", _pdf())

		result = attachment.get_attachments(grievance=self.grievance.name)
		rows = result["data"]

		self.assertEqual(len(rows), 2)
		self.assertEqual({r["file_name"] for r in rows}, {"one.jpg", "two.pdf"})
		self.assertTrue(all(r["servable"] is False for r in rows))

	def test_an_infected_file_is_still_listed(self):
		"""An officer needs to know something was submitted and what became of it."""
		name = self._send("bad.jpg", _jpeg())["data"]["attachment"]
		frappe.db.set_value("Grievance Attachment", name, "scan_status", "Infected")

		rows = attachment.get_attachments(grievance=self.grievance.name)["data"]
		self.assertEqual(len(rows), 1)
		self.assertEqual(rows[0]["scan_status"], "Infected")
		self.assertFalse(rows[0]["servable"])


class TestLimits(AttachmentAPITestCase):
	def test_a_case_cannot_carry_more_than_the_cap(self):
		for i in range(attachment.MAX_ATTACHMENTS_PER_CASE):
			self._send(f"file{i}.jpg", _jpeg())

		result = self._send("one-too-many.jpg", _jpeg())
		self.assertEqual(result["status"], "error")


class TestDeletion(AttachmentAPITestCase):
	def test_an_attachment_can_be_removed_while_the_case_is_open(self):
		name = self._send("mistake.jpg", _jpeg())["data"]["attachment"]

		result = attachment.delete(attachment=name)
		self.assertEqual(result["status"], "success")
		self.assertFalse(frappe.db.exists("Grievance Attachment", name))

	def test_evidence_cannot_be_removed_once_the_case_is_closed(self):
		"""It is part of what the decision rested on.

		handle_api_errors rolls the request back before returning the envelope, so
		the assertion is on the refusal rather than on the row outliving it.
		"""
		name = self._send("evidence.jpg", _jpeg())["data"]["attachment"]
		frappe.db.set_value("Grievance", self.grievance.name, "status", "Closed")

		result = attachment.delete(attachment=name)
		self.assertEqual(result["status"], "error")
		self.assertIn("Closed", result["message"])


def a_draft(client_uuid="draft-uuid-0001"):
	"""An open draft, the state the wizard is in before the case exists."""
	return frappe.get_doc(
		{
			"doctype": "Grievance Draft",
			"client_uuid": client_uuid,
			"step_reached": 2,
			"payload": '{"description": "still typing"}',
		}
	).insert(ignore_permissions=True)


class DraftAttachmentTestCase(FrappeTestCase):
	"""The wizard uploads before the Grievance exists.

	Every test above goes through `grievance=`. This half of the endpoint was
	shipped untested, which is how the draft path came to write a different set of
	columns than the grievance path does.
	"""

	def setUp(self):
		self.draft = a_draft()
		self._saved_request = getattr(frappe.local, "request", None)

	def tearDown(self):
		frappe.local.request = self._saved_request
		frappe.db.rollback()

	def _send(self, filename, content, **kwargs):
		frappe.local.request = _Request(_Upload(filename, content))
		kwargs.setdefault("client_uuid", self.draft.client_uuid)
		return attachment.submit_document(**kwargs)

	def _rows(self):
		return frappe.get_all(
			"Grievance Attachment",
			filters={"draft": self.draft.name},
			fields=["name", "mime_type", "checksum_sha256", "document_type", "file_url", "scan_status"],
		)


class TestDraftUpload(DraftAttachmentTestCase):
	def test_a_file_can_be_attached_to_an_open_draft(self):
		result = self._send("receipt.jpg", _jpeg())
		self.assertEqual(result["status"], "success")
		self.assertEqual(len(self._rows()), 1)

	def test_the_draft_row_records_the_sniffed_type(self):
		"""Not left null to be guessed later: the bytes are only here once."""
		self._send("receipt.jpg", _jpeg())
		self.assertEqual(self._rows()[0]["mime_type"], "image/jpeg")

	def test_the_draft_row_records_a_real_sha256(self):
		"""Core's content_hash is MD5. A field named checksum_sha256 must not hold one."""
		self._send("receipt.jpg", _jpeg())
		digest = self._rows()[0]["checksum_sha256"]

		self.assertEqual(len(digest), 64, "a SHA-256 digest is 64 hex characters")
		int(digest, 16)

	def test_the_document_type_survives(self):
		self._send("receipt.jpg", _jpeg(), document_type="Receipt")
		self.assertEqual(self._rows()[0]["document_type"], "Receipt")

	def test_an_executable_renamed_to_jpg_is_refused_on_a_draft_too(self):
		result = self._send("holiday.jpg", WINDOWS_EXECUTABLE)
		self.assertEqual(result["status"], "error")

	def test_coordinates_are_stripped_on_the_draft_path_too(self):
		original = _jpeg(with_gps=True)
		self.assertTrue(scanning.has_location_metadata(original))

		self._send("field.jpg", original)
		row = self._rows()[0]
		file_name = frappe.db.get_value("File", {"file_url": row["file_url"]}, "name")
		content = frappe.get_doc("File", file_name).get_content()
		self.assertFalse(scanning.has_location_metadata(content))

	def test_a_submitted_draft_takes_no_more_files(self):
		grievance = a_grievance()
		frappe.db.set_value("Grievance Draft", self.draft.name, "submitted_as", grievance.name)

		result = self._send("late.jpg", _jpeg())
		self.assertEqual(result["status"], "error")


class TestDraftLimits(DraftAttachmentTestCase):
	def test_a_draft_cannot_carry_more_than_the_cap(self):
		"""Otherwise the cap is a suggestion: fill a draft, then submit it."""
		for i in range(attachment.MAX_ATTACHMENTS_PER_CASE):
			self._send(f"file{i}.jpg", _jpeg())

		result = self._send("one-too-many.jpg", _jpeg())
		self.assertEqual(result["status"], "error")


class TestDraftBecomesGrievance(DraftAttachmentTestCase):
	def test_the_files_move_to_the_case_with_their_metadata_intact(self):
		"""The row is not rebuilt at submission -- rebuilding is what lost the type."""
		self._send("receipt.jpg", _jpeg(), document_type="Receipt")
		before = self._rows()[0]

		grievance = a_grievance()
		submission.attach_draft_files(self.draft.name, grievance.name)

		moved = frappe.get_all(
			"Grievance Attachment",
			filters={"grievance": grievance.name},
			fields=["mime_type", "checksum_sha256", "document_type", "draft"],
		)
		self.assertEqual(len(moved), 1)
		self.assertEqual(moved[0]["mime_type"], before["mime_type"])
		self.assertEqual(moved[0]["checksum_sha256"], before["checksum_sha256"])
		self.assertEqual(moved[0]["document_type"], "Receipt")
		self.assertFalse(moved[0]["draft"], "the draft link is cleared once the case owns it")

	def test_moving_twice_does_not_duplicate_the_evidence(self):
		self._send("receipt.jpg", _jpeg())
		grievance = a_grievance()

		submission.attach_draft_files(self.draft.name, grievance.name)
		submission.attach_draft_files(self.draft.name, grievance.name)

		rows = frappe.get_all("Grievance Attachment", filters={"grievance": grievance.name})
		self.assertEqual(len(rows), 1)


class TestAbandonedDraftsLeaveNothingBehind(DraftAttachmentTestCase):
	def test_purging_a_draft_removes_its_files(self):
		"""Frappe does not cascade File deletion, so an abandoned wizard would
		otherwise leave its uploads on disk permanently."""
		from oan_grievance_service.api.v1 import draft as draft_api

		self._send("receipt.jpg", _jpeg())
		file_url = self._rows()[0]["file_url"]
		self.assertTrue(frappe.db.exists("File", {"file_url": file_url}))

		frappe.db.set_value("Grievance Draft", self.draft.name, "expires_on", "2020-01-01 00:00:00")
		draft_api.purge_expired_drafts()

		self.assertFalse(frappe.db.exists("Grievance Draft", self.draft.name))
		self.assertFalse(frappe.db.exists("File", {"file_url": file_url}))
		self.assertFalse(frappe.db.exists("Grievance Attachment", {"draft": self.draft.name}))


class TestAGuestCanAttachToTheirOwnDraft(DraftAttachmentTestCase):
	"""The half of the wizard that was unreachable.

	draft.save and draft.load are already open to a guest, because the wizard saves
	progress before the submitter has registered. The upload was not, so a farmer
	could describe their evidence and then be refused when attaching it.
	"""

	def test_a_guest_may_upload_against_a_draft(self):
		self.addCleanup(frappe.set_user, "Administrator")
		frappe.set_user("Guest")

		result = self._send("receipt.jpg", _jpeg())
		self.assertEqual(result["status"], "success")

	def test_a_guest_may_not_upload_against_a_grievance(self):
		"""The draft's client_uuid is the capability. A case has an owner instead."""
		grievance = a_grievance()
		self.addCleanup(frappe.set_user, "Administrator")
		frappe.set_user("Guest")

		frappe.local.request = _Request(_Upload("receipt.jpg", _jpeg()))
		result = attachment.submit_document(grievance=grievance.name)
		self.assertEqual(result["status"], "error")


class TestTheTrailSaysWhatHappened(AttachmentAPITestCase):
	def test_a_deletion_is_recorded_as_a_deletion(self):
		"""It was being written as view_attachment, which files the one event an
		auditor is looking for among the thousands they are not."""
		from oan_grievance_service.services import audit

		name = self._send("mistake.jpg", _jpeg())["data"]["attachment"]
		attachment.delete(attachment=name)

		actions = frappe.get_all(
			"Grievance Access Audit Event",
			filters={"grievance": self.grievance.name},
			pluck="action",
		)
		self.assertIn(audit.ACTION_DELETE_ATTACHMENT, actions)
