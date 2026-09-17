# Copyright (c) 2026, COSS - Centre for Open Societal Systems and contributors
# For license information, please see license.txt

import frappe
from frappe import _
from frappe.model.document import Document

# The prototype's evidence panel states the limits, and the backend has to hold
# them rather than trust them: "Max 10 MB - JPG, PNG, PDF, MP3".
MAX_SIZE_BYTES = 10 * 1024 * 1024

# MP3 is deliberate. A voice note is how a submitter with limited literacy
# describes what happened, and on the IVR channel it may be the only evidence
# that exists.
ALLOWED_MIME_TYPES = {
	"image/jpeg",
	"image/png",
	"application/pdf",
	"audio/mpeg",
}

EXTENSION_FOR_MIME = {
	"image/jpeg": (".jpg", ".jpeg"),
	"image/png": (".png",),
	"application/pdf": (".pdf",),
	"audio/mpeg": (".mp3",),
}

SCAN_PENDING = "Pending"
SCAN_CLEAN = "Clean"
SCAN_INFECTED = "Infected"


class GrievanceAttachment(Document):
	def validate(self):
		self.validate_owner()
		self.validate_uploader()
		self.validate_size()
		self.validate_type()
		self.validate_response_belongs_to_grievance()

	def validate_owner(self):
		"""Evidence belongs to exactly one thing: a case, or the draft that becomes one.

		Neither means an orphan nothing will ever purge; both means two owners
		disagreeing about who the file belongs to once the draft is submitted.
		"""
		if bool(self.grievance) == bool(self.draft):
			frappe.throw(
				_("An attachment must belong to either a grievance or a draft, not both."),
				title=_("Ambiguous Owner"),
			)

	def validate_uploader(self):
		"""Every file is attributable to whoever put it there.

		FR-10 needs the trail to name a person for each piece of evidence, and an
		attachment with no uploader is evidence nobody is answerable for.
		"""
		if self.uploaded_by_user or self.uploaded_by_submitter:
			return

		# A file uploaded from the wizard has no one to name yet: the submitter has
		# not registered, which is the whole reason drafts are reachable without a
		# token. The draft's client_uuid stands in until submission, and
		# attach_draft_files stamps the owner the moment the case exists.
		if self.draft:
			return

		frappe.throw(
			_("An attachment must record who uploaded it."),
			title=_("Uploader Required"),
		)

	def validate_size(self):
		if self.size_bytes and self.size_bytes > MAX_SIZE_BYTES:
			frappe.throw(
				_("{0} is {1} MB. The limit is {2} MB.").format(
					frappe.bold(self.file_name),
					round(self.size_bytes / (1024 * 1024), 1),
					MAX_SIZE_BYTES // (1024 * 1024),
				),
				title=_("File Too Large"),
			)

	def validate_type(self):
		"""Accept only what the evidence panel offers, judged on the sniffed type.

		The extension is checked too, but only for agreement: a file renamed from
		.exe to .jpg still reports its real type, and a .jpg whose contents are a
		PDF is a sign something went wrong upstream. Either mismatch is refused.
		"""
		if not self.mime_type:
			return

		if self.mime_type not in ALLOWED_MIME_TYPES:
			frappe.throw(
				_("{0} files are not accepted. Allowed: JPG, PNG, PDF and MP3.").format(self.mime_type),
				title=_("Unsupported File Type"),
			)

		name = (self.file_name or "").lower()
		expected = EXTENSION_FOR_MIME[self.mime_type]
		if name and not name.endswith(expected):
			frappe.throw(
				_("{0} does not match its contents, which are {1}.").format(
					frappe.bold(self.file_name), self.mime_type
				),
				title=_("Extension Does Not Match Content"),
			)

	def validate_response_belongs_to_grievance(self):
		"""A response-scoped attachment cannot point at another case's response."""
		if not self.response:
			return

		owner = frappe.db.get_value("Grievance Response", self.response, "grievance")
		if owner and owner != self.grievance:
			frappe.throw(
				_("Response {0} belongs to grievance {1}, not {2}.").format(
					frappe.bold(self.response), frappe.bold(owner), frappe.bold(self.grievance)
				),
				title=_("Response Does Not Match Grievance"),
			)

	def is_servable(self):
		"""Whether this file may be handed to a reader.

		Gated on the scan rather than on permissions: a public intake system takes
		arbitrary files from the internet and then asks government staff to open
		them, so an unscanned pipeline is a malware channel with an official
		letterhead. Pending and Infected both withhold the object; the row and its
		audit trail stay either way.
		"""
		return self.scan_status == SCAN_CLEAN


def has_permission(doc, ptype="read", user=None, debug=False):
	"""Deny read on an attachment whose file has not been cleared.

	Registered in hooks.py, and the reason is core's File: a private file resolves
	its permission against whatever it is attached to (File.has_permission). While
	these rows were attached to the Grievance, anyone who could read the case could
	fetch /private/files/<name> directly and never touch download(), so the scan
	gate guarded a door beside an open window.

	Attaching the File to this row instead puts that native check here, where the
	scan verdict lives. Listing is unaffected: get_attachments() reads with
	ignore_permissions and applies its own case-level check, because an officer
	does need to see that an infected file was submitted.
	"""
	if ptype not in ("read", "write", "delete"):
		return True

	if isinstance(doc, str):
		doc = frappe.get_doc("Grievance Attachment", doc)

	return bool(doc.is_servable())
