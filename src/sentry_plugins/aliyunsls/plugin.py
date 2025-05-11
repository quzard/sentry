import logging
from collections.abc import MutableMapping
from typing import Any

from sentry.eventstore.models import Event
from sentry.integrations.base import FeatureDescription, IntegrationFeatures
from sentry.plugins.bases.data_forwarding import DataForwardingPlugin
from sentry.shared_integrations.exceptions import ApiError, ApiHostError, ApiTimeoutError
from sentry.utils import metrics
from sentry.utils.hashlib import md5_text
from sentry_plugins.anonymizeip import anonymize_ip
from sentry_plugins.base import CorePluginMixin
from sentry_plugins.utils import get_secret_field_config

from .client import AliyunSlsApiClient

logger = logging.getLogger(__name__)

SETUP_URL = "https://www.alibabacloud.com/help/en/log-service"

DESCRIPTION = """
Send Sentry events to Aliyun Log Service (SLS).
"""


class AliyunSlsPlugin(CorePluginMixin, DataForwardingPlugin):
    """
    Forward Sentry events to Aliyun Log Service (SLS).

    To configure this plugin, you will need:
    - Aliyun SLS Endpoint (e.g., `cn-hangzhou.log.aliyuncs.com`)
    - Aliyun SLS Project name
    - Aliyun SLS Logstore name
    - Aliyun AccessKey ID
    - Aliyun AccessKey Secret

    The plugin will send logs to the specified Project and Logstore.
    Ensure the AccessKey has sufficient permissions to write logs.
    """

    title = "Aliyun SLS"
    slug = "aliyun-sls"
    description = DESCRIPTION
    conf_key = "aliyun_sls"
    resource_links = [("Aliyun SLS Setup", SETUP_URL)] + CorePluginMixin.resource_links
    required_field = "endpoint"
    project_endpoint: str | None = None
    project_name: str | None = None
    project_logstore: str | None = None
    project_access_key_id: str | None = None
    project_access_key_secret: str | None = None

    feature_descriptions = [
        FeatureDescription(
            """
            Forward Sentry errors and events to Aliyun Log Service.
            """,
            IntegrationFeatures.DATA_FORWARDING,
        )
    ]

    def get_rate_limit(self) -> tuple[int, int]:
        # number of requests, number of seconds (window)
        return (1000, 1)

    def get_config(self, project, user=None, initial=None, add_additional_fields: bool = False):
        return [
            {
                "name": "endpoint",
                "label": "SLS Endpoint",
                "type": "string",
                "required": True,
                "help": "The public endpoint for your Aliyun SLS project (e.g., cn-hangzhou.log.aliyuncs.com).",
                "placeholder": "e.g. cn-hangzhou.log.aliyuncs.com",
            },
            {
                "name": "project",
                "label": "SLS Project",
                "type": "string",
                "required": True,
                "help": "Your Aliyun SLS Project name.",
            },
            {
                "name": "logstore",
                "label": "SLS Logstore",
                "type": "string",
                "required": True,
                "help": "Your Aliyun SLS Logstore name within the project.",
            },
            {
                "name": "access_key_id",
                "label": "AccessKey ID",
                "type": "string",
                "required": True,
                "help": "Your Aliyun AccessKey ID.",
            },
            get_secret_field_config(
                name="access_key_secret",
                label="AccessKey Secret",
                secret=self.get_option("access_key_secret", project),
                help_text="Your Aliyun AccessKey Secret.",
            ),
            {
                "name": "sls_topic",
                "label": "SLS Topic (Optional)",
                "type": "string",
                "required": False,
                "default": "sentry",
                "help": "Topic to associate with the logs in Aliyun SLS.",
            },
            {
                "name": "sls_source",
                "label": "SLS Source (Optional)",
                "type": "string",
                "required": False,
                "help": "Source to associate with the logs. If empty, event's server_name or IP will be used, or 'sentry_server'.",
            },
        ]

    def get_event_payload_properties(self, event: Event) -> dict[str, Any]:
        props = {
            "sentry_event_id": event.event_id,
            "sentry_issue_id": event.group_id,
            "sentry_project_slug": event.project.slug,
            "sentry_transaction": event.get_tag("transaction") or "",
            "sentry_release": event.get_tag("sentry:release") or "",
            "sentry_environment": event.get_tag("sentry:environment") or "",
            "sentry_event_type": event.get_event_type(),
            **{f"sentry_tag_{k.replace('.', '_')}": v for k, v in event.tags}
        }

        for key, value in event.interfaces.items():
            if key == "request":
                headers = value.headers
                if not isinstance(headers, dict):
                    headers = dict(headers or ())

                props.update(
                    {
                        "http_url": value.url,
                        "http_method": value.method,
                        "http_referer": headers.get("Referer", ""),
                    }
                )
            elif key == "exception":
                if value.values:
                    exc = value.values[0]
                    props.update({"exception_type": exc.type, "exception_value": exc.value})
            elif key == "logentry":
                props.update({"log_message": value.formatted or value.message})
            elif key in ("csp", "expectct", "expectstable", "hpkp"):
                props.update(
                    {
                        f"{key.rsplit('.', 1)[-1].lower()}_{k.replace('-', '_')}": v
                        for k, v in value.to_json().items()
                    }
                )
            elif key == "user":
                user_payload: dict[str, Any] = {}
                if value.id:
                    user_payload["user_id"] = value.id
                if value.email:
                    user_payload["user_email_hash"] = md5_text(value.email).hexdigest()
                if value.ip_address:
                    user_payload["user_ip_truncated"] = anonymize_ip(value.ip_address)
                if user_payload:
                    props.update(user_payload)
        return props

    def initialize_variables(self, event: Event) -> None:
        self.project_endpoint = self.get_option("endpoint", event.project)
        self.project_name = self.get_option("project", event.project)
        self.project_logstore = self.get_option("logstore", event.project)
        self.project_access_key_id = self.get_option("access_key_id", event.project)
        self.project_access_key_secret = self.get_option("access_key_secret", event.project)
        self.project_sls_topic = self.get_option("sls_topic", event.project) or "sentry"

        default_source = event.get_tag("server_name")
        if not default_source:
            user_interface = event.interfaces.get("user")
            if user_interface and user_interface.ip_address:
                default_source = user_interface.ip_address
            else:
                default_source = "sentry_server"

        self.project_sls_source = self.get_option("sls_source", event.project) or default_source

    def get_rl_key(self, event: Event) -> str | None:
        if not self.project_access_key_id or not self.project_endpoint or not self.project_name:
            return None
        return f"{self.conf_key}:{md5_text(self.project_endpoint + self.project_name + self.project_access_key_id).hexdigest()}"

    def is_ratelimited(self, event: Event) -> bool:
        if super().is_ratelimited(event):
            metrics.incr(
                "integrations.aliyun_sls.forward_event.rate_limited",
                tags={"event_type": event.get_event_type()},
            )
            return True
        return False

    def get_event_payload(self, event: Event) -> dict[str, Any]:
        log_item = {
            "time": int(event.datetime.timestamp()),
            **self.get_event_payload_properties(event),
        }

        payload = {
            "__topic__": self.project_sls_topic,
            "__source__": self.project_sls_source,
            "__logs__": [log_item],
        }
        return payload

    def forward_event(self, event: Event, payload: MutableMapping[str, Any]) -> bool:
        if not (
            self.project_endpoint
            and self.project_name
            and self.project_logstore
            and self.project_access_key_id
            and self.project_access_key_secret
        ):
            metrics.incr(
                "integrations.aliyun_sls.forward_event.unconfigured",
                tags={"event_type": event.get_event_type()},
            )
            return False

        client = AliyunSlsApiClient(
            endpoint=self.project_endpoint,
            project_name=self.project_name,
            logstore_name=self.project_logstore,
            access_key_id=self.project_access_key_id,
            access_key_secret=self.project_access_key_secret,
        )

        try:
            client.request(payload)
        except Exception as exc:
            metric = "integrations.aliyun_sls.forward_event.error"
            metrics.incr(metric, tags={"event_type": event.get_event_type()})
            logger.info(
                metric,
                extra={
                    "sls_project": self.project_name,
                    "sls_logstore": self.project_logstore,
                    "sls_endpoint": self.project_endpoint,
                    "project_id": event.project_id,
                    "organization_id": event.project.organization_id,
                    "error": str(exc),
                },
            )

            if isinstance(exc, ApiError) and (
                isinstance(exc, (ApiHostError, ApiTimeoutError))
            ):
                return False
            raise

        metrics.incr(
            "integrations.aliyun_sls.forward_event.success",
            tags={"event_type": event.get_event_type()}
        )
        return True
