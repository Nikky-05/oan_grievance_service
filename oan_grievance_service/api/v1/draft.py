"""Save and resume a partially completed submission.

FSD 7 targets farmers on low-connectivity channels and FSD 3.2.1 specifies an
offline-first app. Both make a four-step wizard that only persists on the final
step the wrong shape: the connection is most likely to drop precisely while the
submitter is typing a long description.

A draft is working state, not a record. It is stored unvalidated -- an incomplete
submission is one the Grievance doctype would reject -- and it is cleared on a
schedule once it expires.
"""

import json

import frappe
from frappe import _
from frappe.utils import add_days, now_datetime
from oan_auth_service.api.utils import handle_api_errors, success_response

from oan_grievance_service.services import submission

DRAFT_LIFETIME_DAYS = 30


@frappe.whitelist(allow_guest=True)  # nosemgrep: frappe-semgrep-rules.rules.security.guest-whitelisted-method
@handle_api_errors
def save(client_uuid: str, payload: str | dict | None = None, step_reached: int | str = 0):
	"""Create or overwrite the draft for `client_uuid`.

	Overwrites rather than merges: the client holds the whole wizard state, so a
	partial merge would let a field the submitter cleared reappear from an earlier
	save.
	"""
	if not client_uuid:
		frappe.throw(_("A draft key is required."), title=_("Missing Draft Key"))

	data = submission.parse_payload(payload)
	name = frappe.db.get_value("Grievance Draft", {"client_uuid": client_uuid}, "name")

	if name:
		doc = frappe.get_doc("Grievance Draft", name)
		_assert_owner(doc)
		if doc.submitted_as:
			frappe.throw(
				_("This draft has already been submitted as {0}.").format(doc.submitted_as),
				title=_("Already Submitted"),
			)
	else:
		doc = frappe.new_doc("Grievance Draft")
		doc.client_uuid = client_uuid
		doc.owner_user = _session_user()

	doc.payload = json.dumps(data, ensure_ascii=False)
	doc.step_reached = max(int(step_reached or 0), doc.step_reached or 0)
	doc.contact_mobile = data.get("contact_mobile")
	doc.expires_on = add_days(now_datetime(), DRAFT_LIFETIME_DAYS)
	doc.save(ignore_permissions=True)

	return success_response(
		data={
			"client_uuid": doc.client_uuid,
			"step_reached": doc.step_reached,
			"expires_on": doc.expires_on,
			"attachment_count": _attachment_count(doc.name),
		},
		message=_("Draft saved"),
	)


@frappe.whitelist(allow_guest=True)  # nosemgrep: frappe-semgrep-rules.rules.security.guest-whitelisted-method
@handle_api_errors
def load(client_uuid: str):
	"""Return a saved draft so the wizard resumes where it stopped."""
	name = frappe.db.get_value("Grievance Draft", {"client_uuid": client_uuid}, "name")
	if not name:
		# DoesNotExistError rather than a bare throw: handle_api_errors reads
		# http_status_code off the exception, and a missing draft is a 404 the client
		# can act on -- start a fresh wizard -- not a 400 that reads like bad input.
		frappe.throw(_("No saved draft found."), frappe.DoesNotExistError, title=_("Not Found"))

	doc = frappe.get_doc("Grievance Draft", name)
	_assert_owner(doc)

	return success_response(
		data={
			"client_uuid": doc.client_uuid,
			"payload": submission.parse_payload(doc.payload),
			"step_reached": doc.step_reached,
			"expires_on": doc.expires_on,
			"submitted_as": doc.submitted_as,
			"attachment_count": _attachment_count(doc.name),
		},
		message=_("Draft loaded"),
	)


@frappe.whitelist(allow_guest=True)  # nosemgrep: frappe-semgrep-rules.rules.security.guest-whitelisted-method
@handle_api_errors
def discard(client_uuid: str):
	"""Delete a draft the submitter abandoned.

	A draft already turned into a grievance is kept: it is what makes a retry of
	`submit` return the original ticket instead of filing a second case.
	"""
	name = frappe.db.get_value("Grievance Draft", {"client_uuid": client_uuid}, "name")
	if not name:
		return success_response(data={"discarded": False}, message=_("No draft to discard"))

	doc = frappe.get_doc("Grievance Draft", name)
	_assert_owner(doc)
	if doc.submitted_as:
		frappe.throw(
			_("This draft became grievance {0} and cannot be discarded.").format(doc.submitted_as),
			title=_("Already Submitted"),
		)

	frappe.delete_doc("Grievance Draft", name, ignore_permissions=True, delete_permanently=True)
	return success_response(data={"discarded": True}, message=_("Draft discarded"))


def purge_expired_drafts():
	"""Daily: clear abandoned drafts. Drafts that became grievances are retained."""
	stale = frappe.get_all(
		"Grievance Draft",
		filters={"expires_on": ["<", now_datetime()], "submitted_as": ["is", "not set"]},
		pluck="name",
	)
	for name in stale:
		_purge_draft_uploads(name)
		frappe.delete_doc("Grievance Draft", name, ignore_permissions=True, delete_permanently=True)
	return len(stale)


def _purge_draft_uploads(draft):
	"""Delete the evidence an abandoned wizard left behind.

	Frappe does not cascade a File when the row it is attached to goes, so without
	this every wizard someone closed halfway leaves its uploads on disk for good --
	and they are private files nobody can now reach, which is the worst of both.
	"""
	rows = frappe.get_all(
		"Grievance Attachment",
		filters={"draft": draft},
		fields=["name", "file_url"],
	)
	for row in rows:
		file_name = frappe.db.get_value("File", {"file_url": row.file_url}, "name")
		if file_name:
			frappe.delete_doc("File", file_name, force=True, ignore_permissions=True)
		frappe.delete_doc("Grievance Attachment", row.name, force=True, ignore_permissions=True)


def _session_user():
	user = frappe.session.user
	return None if user in ("Guest", None) else user


def _assert_owner(doc):
	"""A draft claimed by a signed-in user stays with that user.

	Anonymous drafts are protected only by the unguessability of the key, which is
	the same guarantee the ticket-number lookup already relies on.
	"""
	user = _session_user()
	if doc.owner_user and user and doc.owner_user != user:
		if "System Manager" not in frappe.get_roles(user):
			frappe.throw(_("This draft belongs to another user."), frappe.PermissionError)


def _attachment_count(draft_name):
	return frappe.db.count("File", {"attached_to_doctype": "Grievance Draft", "attached_to_name": draft_name})
