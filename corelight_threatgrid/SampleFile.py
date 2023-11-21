#!/usr/bin/env python3

import os
import fasteners
import hashlib
import json
import time
import threading
import logging
import magic
import re


META_DIRNAME = ".meta"

THREATGRID_SUPPORTED_EXTENSIONS = set(
    [
        "bat",
        # "bz2",
        "chm",
        "dll",
        "doc",
        "docx",
        "exe",
        # "gz",
        # "gzip",
        "hta",
        "hwp",
        "hwpx",
        "hwt",
        "iso",
        "jar",
        "js",
        "jse",
        "jtd",
        "jtdc",
        "jtt",
        "jttc",
        "lnk",
        "mhtml",
        "msi",
        "pdf",
        "pe32",
        "pe32+",
        "ppt",
        "pptx",
        "ps1",
        "rtf",
        "sep",
        "swf",
        "vbe",
        "vbn",
        "vbs",
        "wsf",
        "xls",
        "xlsx",
        "xml",
        # "xz",
        "zip",
    ]
)

THREATGRID_SUPPORTED_MIME_REGEXES = [
    r"msword",
    r"vnd\.openxmlformats",
    r"java",  # both javascript and java
    r"pdf",
    r"powerpoint",
    r"rtf",
    r"excel",
    r"xml",
]


class SampleFile(object):
    _metadata = None
    _metadata_refresh = 0.0
    _metadata_file = None
    _metadata_dirty = False

    def __enter__(self):
        self._lock.acquire()
        if self._lock._count == 1:
            self._metadata_lock.acquire()
            self._refresh_metadata()

    def __exit__(self, type, value, traceback):
        if self._lock._count == 1:
            self._save_metadata()
            self._metadata_lock.release()
        self._lock.release()

    def __init__(self, filename, api):
        self._filename = filename
        self._filebase = os.path.basename(filename)
        self._filedir = os.path.dirname(filename)

        self.logger = logging.getLogger(name="samplefile")

        self._api = api

        self._lock = threading._RLock()

        self.init_metadata()

        # hold the lock to coalesce writes
        with self:
            self.calc_sha1()
            self.calc_sha256()

            # file type
            self.get_magic()

            # other analysis?

    def calc_hash(self, hash_obj, metadata_key):
        with self:
            if metadata_key in self._metadata:
                return self._metadata[metadata_key]
            h = hash_obj()
            b = bytearray(128 * 1024)
            mv = memoryview(b)
            with open(self._filename, "rb") as f:
                for n in iter(lambda: f.readinto(mv), 0):
                    h.update(mv[:n])

            digest = h.hexdigest()
        self.set_metadata(metadata_key, digest)
        return digest

    def calc_sha1(self):
        return self.calc_hash(hashlib.sha1, "sha1")

    def calc_sha256(self):
        return self.calc_hash(hashlib.sha256, "sha256")

    def init_metadata(self):
        # set up locks, load cached metadata, if it exists
        self._metadata_dir = os.path.join(self._filedir, META_DIRNAME)
        os.makedirs(self._metadata_dir, mode=0o770, exist_ok=True)

        metadata_lock_path = os.path.join(self._metadata_dir, f"{self._filebase}.lock")
        self._metadata_lock = fasteners.InterProcessLock(metadata_lock_path)

        with self:
            if self._metadata is None:
                self._metadata_file = os.path.join(
                    self._metadata_dir, f"{self._filebase}.meta"
                )
                self._metadata = {}
                if not os.path.exists(self._metadata_file):
                    self.save_metadata()
                # check to see if we have stored metadata
                self._refresh_metadata()

    def set_metadata(self, key, value):
        with self:
            self._metadata[key] = value
            self.save_metadata()

    def get_metadata(self, key, default=None):
        with self:
            return self._metadata.get(key, default)

    def save_metadata(self):
        self._metadata_dirty = True

    def _save_metadata(self):
        if not self._metadata_dirty:
            return
        with self:
            file_ts = 0
            if os.path.isfile(self._metadata_file):
                md_stat = os.stat(self._metadata_file)
                file_ts = md_stat.st_mtime
            with open(self._metadata_file, "w") as f:
                json.dump(self._metadata, f, indent=2)
            md_stat2 = os.stat(self._metadata_file)
            if md_stat2.st_mtime <= file_ts:
                # FIXME: ext4 timestamp resolution is in ns, but other factors may
                # reduce it to ms in practice -- we don't want to miss any updates, so
                # make sure the timestamp changes between writes
                print("WARNING: new timestamp did not change!")
                time.sleep(0.005)  # try again later
                self._save_metadata()
            else:
                self._metadata_refresh = md_stat2.st_mtime
            self._metadata_dirty = False

    def _refresh_metadata(self):
        if self._metadata_file is None:
            # not initialized yet
            return
        with self:
            if os.path.exists(self._metadata_file):
                md_stat = os.stat(self._metadata_file)
                curr = time.time()
                if md_stat.st_mtime > curr:
                    raise Exception("file changed in the future?")

                if md_stat.st_mtime <= self._metadata_refresh:
                    return
                with open(self._metadata_file) as f:
                    self._metadata = json.load(f)
                    self._metadata_refresh = md_stat.st_mtime

    def submit_threatgrid(self):
        data = self.check_threatgrid()
        if data is False:
            self.logger.warn(
                f"not submitting unsupported {self._filename!r} to threatgrid"
            )
            return data
        if not data["data"]["items"]:
            self.logger.warn(f"submitting {self._filename!r} to threatgrid")
            # tags is a comma-separated string
            self._api.submit_sample(self._filename, tags="Corelight")
        return data

    def check_threatgrid(self):
        supported = self.get_metadata("threatgrid_supported")
        if supported is None:
            mime, human = self.get_metadata("magic")
            extension = self._filename.split(".")[-1]
            if (
                2 <= len(extension) <= 4
                and extension in THREATGRID_SUPPORTED_EXTENSIONS
            ):
                self.logger.info(
                    f"extension {extension} is supported for {self._filename!r}"
                )
                supported = True
            else:
                for regex in THREATGRID_SUPPORTED_MIME_REGEXES:
                    if re.search(regex, mime):
                        self.logger.info(
                            f"mime type {mime} is supported for {self._filename!r}"
                        )
                        supported = True
                        break
            if supported is None:
                self.logger.warning(
                    "file extension/mime type not supported for {self._filename!r}"
                )
                supported = False
            self.set_metadata("threatgrid_supported", supported)
        if supported is False:
            return supported
        # already submitted ? update metadata : submit + update metadata
        data = self.get_metadata("threatgrid_info")
        if data is not None:
            # already there
            return data
        data = self._api.get_samples(sha256=self.get_metadata("sha256"))
        if data["data"]["items"]:
            self.set_metadata("threatgrid_info", data)
        else:
            self.logger.info(
                f"no threatgrid samples found for {self._filename!r} "
                f"using sha256 {self.get_metadata('sha256')}"
            )
        return data

    def get_magic(self):
        _magic = self.get_metadata("magic")
        if _magic is None:
            _magic = (None, None)
        mime, human = _magic

        if mime is None:
            mime = magic.from_file(self._filename, mime=True)

        if human is None:
            human = magic.from_file(self._filename)

        _magic = (mime, human)

        self.set_metadata("magic", _magic)

        return _magic
