app_name = "oan_grievance_service"
app_title = "Grievance Management"
app_publisher = "COSS - Centre for Open Societal Systems"
app_description = "OpenAgriNet Ethiopia Grievance Management Module: multi-channel grievance intake, routing, SLA tracking and escalation"
app_email = "admin@openagrinet.org"
app_license = "mit"

# Apps
# ------------------

required_apps = ["oan_auth_service"]

add_to_apps_screen = [
	{
		"name": "oan_grievance_service",
		"title": "Grievance Management",
		"route": "/app/grievance",
	}
]

# Installation
# ------------------
# FSD Appendix F roles, 3.2.2 categories, 3.11.8 regions and the Appendix C
# notification matrix are seeded so a fresh site comes up usable.

after_install = "oan_grievance_service.setup.install.after_install"
after_migrate = "oan_grievance_service.setup.install.after_migrate"

# Permissions
# ------------------
# FSD 3.1.1 deny-by-default RBAC. The query condition filters list views, reports and
# the API uniformly; has_permission mirrors it for a single document.

permission_query_conditions = {
	"Grievance": "oan_grievance_service.permissions.grievance_query_conditions",
}

has_permission = {
	"Grievance": "oan_grievance_service.permissions.has_grievance_permission",
	# Core's File resolves a private file's permission against whatever it is
	# attached to, so this is what stops /private/files/<name> serving an unscanned
	# object behind download()'s back.
	"Grievance Attachment": (
		"oan_grievance_service.grievance_management.doctype.grievance_attachment"
		".grievance_attachment.has_permission"
	),
}

# Document Events
# ------------------
# FSD 4.1 step 7 routes on submission. FSD 3.5 advances the lifecycle when a
# structured response is filed. FSD 3.3.1 gates reassignment on L2 approval.
# FR-10 records every read of a case.

_CLEAR_LOOKUP_CACHE = {
	"on_update": "oan_grievance_service.api.v1.submission.clear_reference_cache",
	"after_delete": "oan_grievance_service.api.v1.submission.clear_reference_cache",
}

doc_events = {
	"Grievance": {
		"after_insert": "oan_grievance_service.services.hooks_handlers.grievance_after_insert",
		"onload": "oan_grievance_service.services.audit.on_grievance_view",
	},
	"Grievance Response": {
		"after_insert": "oan_grievance_service.services.hooks_handlers.response_after_insert",
	},
	"Grievance Reassignment Request": {
		"on_update": "oan_grievance_service.services.hooks_handlers.reassignment_on_update",
	},
	"Grievance SLA Deferral": {
		"on_update": "oan_grievance_service.services.hooks_handlers.deferral_on_update",
	},
	"Grievance Anonymity Request": {
		"on_update": "oan_grievance_service.services.hooks_handlers.anonymity_on_update",
	},
	# The submission wizard caches its lookups. An administrator adding a woreda
	# or deactivating a category must see it in the form immediately, not after
	# the cache expires.
	"Grievance Administrative Area": _CLEAR_LOOKUP_CACHE,
	"Grievance Service Category": _CLEAR_LOOKUP_CACHE,
	"Grievance Type": _CLEAR_LOOKUP_CACHE,
	# FSD 3.8: our send path renders per recipient inside print_language(), which only
	# moves _()-marked strings, so a Grievance notification must not carry bare literal
	# text. Extends a core doctype through the supported hook rather than editing it.
	"Notification": {
		"validate": "oan_grievance_service.services.notifications.validate_notification",
	},
}

# Scheduled Tasks
# ------------------
# FSD 4.3: a background process monitors open grievances against their SLA deadlines.
# FSD 7 requires the batch to complete within 30 minutes.

scheduler_events = {
	"hourly": [
		"oan_grievance_service.tasks.send_sla_reminders",
		"oan_grievance_service.tasks.escalate_breached",
		"oan_grievance_service.tasks.dispatch_notifications",
		# Attachments land as Pending and is_servable() withholds anything not yet
		# Clean, so without this every uploaded file stays invisible to officers.
		"oan_grievance_service.tasks.scan_pending_attachments",
	],
	"daily": [
		"oan_grievance_service.tasks.auto_close_expired",
		"oan_grievance_service.tasks.purge_expired_drafts",
	],
}

# Fixtures
# ------------------
# Configuration that must travel with the app rather than be re-keyed per site.

fixtures = [
	{
		"dt": "Role",
		"filters": [
			[
				"name",
				"in",
				[
					"Grievance Submitter",
					"Grievance Officer",
					"Grievance Admin",
				],
			]
		],
	},
]

# Authentication & Registration
# -----------------------------
# Integrates with oan_auth_service to initialize domain profiles upon user registration.

on_user_registered = ["oan_grievance_service.services.hooks_handlers.on_user_registered"]

# Portal
# ------------------
# FSD 3.2.1 lists the web portal as a channel open to all submitter types.

website_route_rules = [
	{"from_route": "/grievance/track/<path:ticket>", "to_route": "grievance-track"},
]
