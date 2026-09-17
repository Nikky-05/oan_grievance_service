"""FR-10 Audit and Compliance.

The Grievance Access Audit Event doctype is FSD section 5's Access Audit Event: it
records reads, which the change log cannot, because reading a grievance changes nothing.
Every question about a breach — who opened this case, who exported a region — is a read.
"""

import frappe
from frappe import _
from frappe.utils import now_datetime

ACTION_VIEW_DETAIL = "view_detail"
ACTION_VIEW_LIST = "view_list"
ACTION_EXPORT = "export"
ACTION_VIEW_ATTACHMENT = "view_attachment"
ACTION_VIEW_SUBMITTER_IDENTITY = "view_submitter_identity"
# The one write in a trail otherwise made of reads. Evidence leaving a case is
# exactly what an auditor asking "what was this decided on" needs to see, and
# recording it as a view -- which is what it was doing -- hides it among them.
ACTION_DELETE_ATTACHMENT = "delete_attachment"


def record_access(action, grievance=None, scope=None, decision="Allowed"):
	"""Write an access audit row. Never raises: auditing must not break the request."""
	try:
		frappe.get_doc(
			{
				"doctype": "Grievance Access Audit Event",
				"timestamp": now_datetime(),
				"user": frappe.session.user,
				"role": primary_role(),
				"grievance": grievance,
				"action": action,
				"decision": decision,
				"scope_evaluated": scope,
				"source": frappe.local.request.path if getattr(frappe.local, "request", None) else "server",
			}
		).insert(ignore_permissions=True)
	except Exception:
		frappe.log_error(title="Access audit write failed", message=frappe.get_traceback())


def primary_role():
	"""The grievance role this user holds, for the audit row."""
	from oan_grievance_service.permissions import GRIEVANCE_ROLES

	roles = set(frappe.get_roles())
	for role in GRIEVANCE_ROLES:
		if role in roles:
			return role
	return None


def on_grievance_view(doc, method=None):
	"""Hooked to onload so opening a case leaves a trace."""
	if frappe.session.user == "Administrator" and frappe.flags.in_install:
		return
	record_access(ACTION_VIEW_DETAIL, grievance=doc.name)


def log_denied(action, grievance=None, scope=None):
	"""FSD UC-02 E1: an unauthorised attempt is denied and logged."""
	record_access(action, grievance=grievance, scope=scope, decision="Denied")


class ImmutableRecord:
	"""Mixin for append-only doctypes: a row may be created, never changed or removed.

	The permission flags on these doctypes already deny write and delete in the desk,
	but permissions are exactly what server code bypasses -- every insert here runs
	with `ignore_permissions=True`, and `db_set` skips the ORM altogether. An audit
	trail whose only defence is a permission flag is one `frappe.db.set_value` away
	from being rewritten, with nothing recording that it happened.

	FR-10 needs the trail to be evidence. Evidence that the application can silently
	revise is not evidence, so the refusal lives in the document lifecycle where the
	service layer cannot step around it.
	"""

	def on_update(self):
		# get_doc_before_save() is None on insert and the prior version on update,
		# which is the only reliable way to tell the two apart in this hook.
		if self.get_doc_before_save():
			frappe.throw(
				_("{0} is an audit record and cannot be modified after it is written.").format(self.doctype),
				title=_("Immutable Record"),
			)

	def on_trash(self):
		frappe.throw(
			_("{0} is an audit record and cannot be deleted.").format(self.doctype),
			title=_("Immutable Record"),
		)
