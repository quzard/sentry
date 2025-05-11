import hashlib
import hmac
import base64
from datetime import datetime, timezone
import json # Ensure json is imported for body serialization and Content-MD5

from sentry_plugins.client import ApiClient


class AliyunSlsApiClient(ApiClient):
    plugin_name = "aliyun_sls"
    allow_redirects = False # SLS typically does not use redirects for API calls
    metrics_prefix = "integrations.aliyun_sls"

    def __init__(self, endpoint: str, project_name: str, logstore_name: str, access_key_id: str, access_key_secret: str):
        self.base_url = f"https://{project_name}.{endpoint.replace('https://', '').replace('http://', '')}"
        self.project_name = project_name # Needed for Host header
        self.logstore_name = logstore_name
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        # SLS API version, check Aliyun documentation for the latest.
        self.sls_api_version = "0.6.0"
        super().__init__(verify_ssl=True) # Typically should verify SSL

    def _get_sls_headers(self, method: str, path: str, body: bytes | None, params: dict | None = None) -> dict:
        headers = {}
        content_type = "application/json" # We send JSON data

        # GMT Date
        # Python's %Z can be unreliable, strftime with fixed UTC offset
        # For Py3.11+ datetime.utcnow().replace(tzinfo=timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        # For older versions, ensure datetime object is timezone-aware (UTC)
        # Using timezone.utc for explicitness
        gmt_date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")

        # Body MD5 (for JSON, it's the MD5 of the UTF-8 encoded string)
        body_md5 = ""
        body_raw_size = "0"
        if body:
            body_md5 = base64.b64encode(hashlib.md5(body).digest()).decode("utf-8")
            body_raw_size = str(len(body))
            headers["Content-MD5"] = body_md5
            headers["Content-Type"] = content_type


        # SLS specific headers
        sls_headers = {
            "x-log-apiversion": self.sls_api_version,
            "x-log-signaturemethod": "hmac-sha1",
            "x-log-bodyrawsize": body_raw_size,
            # "x-log-compresstype": "lz4", # if using compression, not by default
        }
        headers.update(sls_headers)

        # Host header is derived from base_url or explicitly set project.endpoint
        headers["Host"] = f"{self.project_name}.{self.base_url.split('//')[1]}"
        headers["Date"] = gmt_date

        # Construct the string to sign
        # VERB + \n + CONTENT-MD5 + \n + CONTENT-TYPE + \n + DATE + \n + CanonicalizedLOGHeaders + \n + CanonicalizedResource
        canonicalized_log_headers_str = ""
        for key in sorted(sls_headers.keys()):
            canonicalized_log_headers_str += f"{key}:{sls_headers[key]}\n"

        canonicalized_resource_str = path
        if params:
            sorted_params = "&".join(
                f"{k}={v}" for k, v in sorted(params.items())
            )
            canonicalized_resource_str += f"?{sorted_params}"


        string_to_sign = f"{method.upper()}\n{body_md5}\n{content_type if body else ''}\n{gmt_date}\n{canonicalized_log_headers_str}{canonicalized_resource_str}"

        # Sign the string
        signature = base64.b64encode(
            hmac.new(
                self.access_key_secret.encode("utf-8"),
                string_to_sign.encode("utf-8"),
                hashlib.sha1,
            ).digest()
        ).decode("utf-8")

        headers["Authorization"] = f"LOG {self.access_key_id}:{signature}"
        return headers

    def request(self, data: dict):
        # Path for posting logs via load balancing (recommended)
        # Note: The `base_url` already includes `https://{project_name}.{endpoint}`
        # So the path here is just the resource part.
        path = f"/logstores/{self.logstore_name}/shards/lb"

        # Serialize data to JSON string, then encode to bytes for MD5 and bodyrawsize
        json_body_str = json.dumps(data)
        json_body_bytes = json_body_str.encode('utf-8')


        headers = self._get_sls_headers(method="POST", path=path, body=json_body_bytes)

        # The _request method from ApiClient will use self.base_url
        return self._request(
            path=path, # This path is appended to self.base_url
            method="post",
            data=json_body_bytes, # Send raw bytes
            headers=headers,
            json=False, # Body is already serialized bytes, content type is set in headers
            timeout=5, # Keep or adjust timeout
            allow_text=True, # SLS might return non-JSON success/error messages
        )
