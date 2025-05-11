from sentry_plugins.client import ApiClient


class AliyunSlsApiClient(ApiClient):
    plugin_name = "aliyun_sls"
    allow_redirects = False
    metrics_prefix = "integrations.aliyun_sls"

    def __init__(self, endpoint, ak, sk):
        self.endpoint = endpoint
        self.ak = ak
        self.sk = sk
        super().__init__(verify_ssl=False)

    def request(self, data):
        headers = {"Authorization": f"Splunk {self.token}"}
        return self._request(
            path=self.endpoint,
            method="post",
            data=data,
            headers=headers,
            json=True,
            timeout=5,
            allow_text=True,
        )
