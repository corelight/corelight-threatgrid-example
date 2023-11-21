import requests


class ThreatGridAPI(object):
    def __init__(self, api_host, api_key):
        self.api_base = f"https://{api_host}/api/v2"
        self.api_key = api_key

    def submit_sample(self, filename, name=None, private=True, **kw):
        if name is None:
            name = filename
        files = {"sample": (name, open(filename, "rb"))}
        data = {"api_key": self.api_key, "private": private, **kw}
        return requests.post(f"{self.api_base}/samples", data=data, files=files)

    def get_samples(self, **kw):
        params = {"api_key": self.api_key, **kw}
        return requests.get(f"{self.api_base}/samples", params=params).json()
