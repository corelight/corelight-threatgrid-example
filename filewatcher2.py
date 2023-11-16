#!/usr/bin/env python3

from SampleFile import SampleFile
from watchdog.observers import Observer
from watchdog.events import RegexMatchingEventHandler

import logging
import time

import threading
import queue

import os
import re

import requests

from threatgrid_api import ThreatGridAPI

from config import SAMPLES_BASE, SMA_HOST, SMA_API_KEY, HUMIO_BASE, HUMIO_REPOSITORY, HUMIO_TOKEN, HUMIO_VALIDATE_CERT


monitor_path = SAMPLES_BASE
num_consumers = 100

logging.basicConfig(filename='filewatcher2.log', encoding='utf-8', level=logging.DEBUG)


def humio_search_sha1(sha1, session):
    data = session.post(
        f"{HUMIO_BASE}/api/v1/repositories/{HUMIO_REPOSITORY}/query",
        headers={"ACCEPT": "application/json", "Authorization": f"Bearer {HUMIO_TOKEN}"},
        json={
            "queryString": f"#path=files and sha1={sha1}",
            "start": "24hours",
            "end": "now",
        },
        verify=HUMIO_VALIDATE_CERT
    )

    return data.json()


class SampleFileEventHandler(RegexMatchingEventHandler):
    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)

        self.logger = logging.getLogger(name="file_handler")

        self._queue = queue.Queue()
        self._retry_queue = queue.Queue()

    def handle_path(self, path):
        if path in self._queue.queue:
            return
        self._queue.put(path)

    def _handle_path(self, path, session):
        self.logger.info(f"handling {path}")
        sample = SampleFile(path, api=ThreatGridAPI(SMA_HOST, SMA_API_KEY))

        with sample:
            orig_sha1 = os.path.basename(sample._filename).split(".", 1)[0]
            sha1 = sample.get_metadata("sha1")
            if sha1 is None:
                self.logger.critical(f"no sha1 in metadata for {sample._filename}")
            if sha1 != orig_sha1:
                self.logger.error(f"file {sample._filename} is partial download, marking as unsupported")
                sample.set_metadata("threatgrid_supported", False)
            files_log = sample.get_metadata("files_log")
            if files_log is None:
                self.logger.info(f"query logscale for {orig_sha1}")
                files_log = humio_search_sha1(orig_sha1, session=session)
                if len(files_log) > 0:
                    sample.set_metadata("files_log", files_log)
                else:
                    self.logger.error(f"failed to get metadata for {sample._filename} using sha1 {orig_sha1}, adding to retry queue")
                    self._retry_queue.put(sample._filename)

            tags = ["Corelight"]
            orig_filename = os.path.basename(path)
            for entry in files_log:
                if "filename" in entry:
                    orig_filename = '+'.join([orig_filename, entry["filename"]])

                if "@host" in entry:
                    if entry["@host"] == "ap200.bh.local":
                        if "decrypted" not in tags:
                            tags.append("decrypted")
                    elif entry["@host"] == "sensor.bh.local":
                        if "plaintext" not in tags:
                            tags.append("plaintext")
                    else:
                        raise Exception(f"Unrecognized sensor: {entry['@host']}")
                else:
                    raise Exception(f"no sensor in log: {entry}")

            # do stuff here
            result = sample.submit_threatgrid(orig_filename=orig_filename, tags=tags)

        self.logger.info(f"completed {path}")

    def path_handler(self):
        while True:
            session = requests.Session()
            path = self._queue.get()
            if path is None:
                self.logger.info("handler thread exiting")
                return
            self._handle_path(path, session=session)

    def start_handlers(self):
        self._handlers = []
        for i in range(num_consumers):
            t = threading.Thread(target=self.path_handler, daemon=True)
            t.start()
            self._handlers.append(t)

    def stop_handlers(self):
        for i in range(num_consumers):
            self._queue.put(None)
        for t in self._handlers:
            t.join()

    def on_moved(self, event):
        path = event.dest_path
        self.logger.info(f"path {path!r} was {event.event_type}")

        self.handle_path(path)

    def on_created(self, event):
        path = event.src_path
        self.logger.info(f"path {path!r} was {event.event_type}")

        self.handle_path(path)


if __name__ == "__main__":
    observer = Observer()
    file_handler = SampleFileEventHandler(ignore_regexes=[".*/[.].*"])  # this uses re.match :/
    file_handler.start_handlers()
    observer.schedule(file_handler, monitor_path, recursive=True)
    observer.start()

    logger = logging.getLogger()

    try:
        while True:
            walk_info = os.walk(SAMPLES_BASE)
            for root, dirs, files in walk_info:
                for file in files:
                    f = os.path.join(root, file)
                    if re.search(r"/[.]", f):
                        continue
                    if os.path.isfile(os.path.join(root, '.meta', f"{file}.meta")):
                        continue
                    logger.warning(f"no metadata for {f!r}, calling handle_path")
                    file_handler.handle_path(f)
            try:
                while True:
                    file = file_handler._retry_queue.get_nowait()
                    logger.warning(f"retrying {file}")
                    file_handler._queue.put(file)
            except queue.Empty:
                pass
            time.sleep(60)
    finally:
        observer.stop()
        observer.join()
        file_handler.stop_handlers()
