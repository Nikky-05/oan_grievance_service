"""Support for FR-02 submission: contact normalisation, submitter identity, the
location snapshot and draft attachments.

These live behind the API rather than inside the Grievance controller because the
same rules apply to a draft that is not yet a Grievance, and to the submitter
profile that outlives any single case.
"""

import json
import re

import frappe
from frappe import _
from frappe.utils import now_datetime

# FSD 3.11.8 fixes the country to Ethiopia. Ethiopian subscriber numbers are nine
# digits after the country code; mobile ranges open with 9 or 7.
COUNTRY_CODE = "251"
MOBILE_PATTERN = re.compile(r"^[79]\d{8}$")

# The prototype's number field defaults to +255, which is Tanzania. Reject it
# explicitly rather than letting it through as an unrecognised prefix, because a
# wrong-but-plausible country code silently sends every SMS to another network.
CONFUSABLE_CODES = {"255": "Tanzania", "254": "Kenya", "252": "Somalia", "249": "Sudan"}


def normalise_mobile(value):
	"""Return a mobile number as +251XXXXXXXXX, or raise.

	Accepts the three forms a submitter actually types: the international form,
	the national form with a leading zero, and the bare subscriber number.
	"""
	raw = re.sub(r"[^\d+]", "", value or "")
	if not raw:
		frappe.throw(_("A contact mobile number is required."), title=_("Missing Mobile"))

	digits = raw.lstrip("+")

	for code, country in CONFUSABLE_CODES.items():
		if digits.startswith(code) and len(digits) > len(code):
			frappe.throw(
				_("+{0} is the country code for {1}. Ethiopian numbers begin +251.").format(code, country),
				title=_("Wrong Country Code"),
			)

	if digits.startswith(COUNTRY_CODE):
		subscriber = digits[len(COUNTRY_CODE) :]
	elif digits.startswith("0"):
		subscriber = digits[1:]
	else:
		subscriber = digits

	if not MOBILE_PATTERN.match(subscriber):
		frappe.throw(
			_(
				"{0} is not a valid Ethiopian mobile number. Expected nine digits "
				"beginning 9 or 7, for example +251911234567."
			).format(value),
			title=_("Invalid Mobile Number"),
		)

	return f"+{COUNTRY_CODE}{subscriber}"


def find_or_create_submitter(payload):
	"""Resolve the Submitter Profile a grievance belongs to.

	FR-02 duplicate detection matches on the submitter, so a grievance without one
	can never be found to duplicate anything. Identity is the normalised mobile
	number: it is the one field present on every channel including IVR, where
	there is no account and no email.
	"""
	mobile = payload.get("contact_mobile")
	if not mobile:
		return None

	existing = frappe.db.get_value("Grievance Submitter Profile", {"contact_mobile": mobile}, "name")
	if existing:
		return existing

	profile = frappe.get_doc(
		{
			"doctype": "Grievance Submitter Profile",
			"submitter_type": payload.get("submitter_type"),
			"submitter_name": payload.get("submitter_name"),
			"contact_mobile": mobile,
			"contact_email": payload.get("contact_email"),
			# The four-level region/zone/woreda/kebele columns were replaced by a
			# single link into the Administrative Area tree. Frappe drops unknown
			# keys silently, so passing the old names looked like it worked and
			# left every new profile with no location at all.
			"administrative_area": payload.get("administrative_area"),
			"active": 1,
		}
	)
	profile.insert(ignore_permissions=True)
	return profile.name


def attach_draft_files(draft, grievance):
	"""Hand the draft's evidence to the case it became.

	The attachment rows are re-pointed, not rebuilt. Rebuilding them is what lost
	the metadata: the row was reconstructed from the File, which knows a name, a
	size and an MD5 -- so `checksum_sha256` was filled with a hash that is not one,
	`mime_type` came out null, and whatever the submitter had labelled the document
	was dropped. The bytes are only in front of us once, at upload; everything
	derived from them is recorded there and simply travels with the row.

	The File objects do not move at all. They are attached to the attachment row,
	which is what makes core's private-file permission check consult the scan
	verdict, and that row keeps its name across the change of owner.
	"""
	rows = frappe.get_all(
		"Grievance Attachment",
		filters={"draft": draft},
		fields=["name", "uploaded_by_user", "uploaded_by_submitter"],
	)
	submitter = frappe.db.get_value("Grievance", grievance, "submitter")

	for row in rows:
		values = {"grievance": grievance, "draft": None}
		# A guest's upload carried no uploader, because there was no one to name.
		# The case has an owner now, and FR-10 wants every file attributable.
		if not (row.uploaded_by_user or row.uploaded_by_submitter):
			values["uploaded_by_submitter"] = submitter
		frappe.db.set_value("Grievance Attachment", row.name, values, update_modified=False)

	return len(rows)


def record_consent(doc):
	"""FSD 9: consent is mandatory and its time of capture is part of the record."""
	if not doc.consent_given:
		frappe.throw(
			_("The submitter must consent to the processing of their personal data."),
			title=_("Consent Required"),
		)
	if not doc.consent_recorded_at:
		doc.consent_recorded_at = now_datetime()


def parse_payload(payload):
	"""Draft payloads arrive as a JSON string over HTTP and as a dict in tests."""
	if isinstance(payload, dict):
		return payload
	if not payload:
		return {}
	try:
		parsed = json.loads(payload)
	except (TypeError, ValueError):
		frappe.throw(_("Draft payload is not valid JSON."), title=_("Malformed Draft"))
	if not isinstance(parsed, dict):
		frappe.throw(_("Draft payload must be an object."), title=_("Malformed Draft"))
	return parsed
