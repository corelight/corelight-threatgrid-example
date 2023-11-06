#!/usr/bin/env python3

from SampleFile import SampleFile
from watchdog.observers import Observer
from watchdog.events import RegexMatchingEventHandler

import logging
import time

import threading
import queue

from threatgrid_api import ThreatGridAPI

from config import SAMPLES_BASE, SMA_HOST, SMA_API_KEY


monitor_path = SAMPLES_BASE
num_consumers = 10

logging.basicConfig(filename='filewatcher2.log', encoding='utf-8', level=logging.DEBUG)


class SampleFileEventHandler(RegexMatchingEventHandler):
    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)

        self.logger = logging.getLogger(name="file_handler")

        self._queue = queue.Queue()

    def handle_path(self, path):
        if path in self._queue.queue:
            return
        self._queue.put(path)

    def _handle_path(self, path):
        self.logger.info(f"handling {path}")
        sample = SampleFile(path, api=ThreatGridAPI(SMA_HOST, SMA_API_KEY))

        with sample:
            # do stuff here
            result = sample.submit_threatgrid()

        self.logger.info(f"completed {path}")

    def path_handler(self):
        while True:
            path = self._queue.get()
            if path is None:
                self.logger.info("handler thread exiting")
                return
            self._handle_path(path)

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


if __name__ == "__main__":
    observer = Observer()
    file_handler = SampleFileEventHandler()
    file_handler.start_handlers()
    observer.schedule(file_handler, monitor_path, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(10)
    finally:
        observer.stop()
        observer.join()
        file_handler.stop_handlers()
