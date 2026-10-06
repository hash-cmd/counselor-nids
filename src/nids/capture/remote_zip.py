"""Read single members of a large remote zip with HTTP range requests.

The CSE-CIC-IDS2018 raw captures are one 40-60 GB zip per day. A zip keeps its table of
contents at the end, so with range requests one host's capture can be fetched without
downloading the whole archive.
"""

import io
import shutil
import urllib.request
import zipfile
from pathlib import Path


class HttpFile(io.RawIOBase):
    """A seekable, read-only file over HTTP range requests."""

    def __init__(self, url: str, timeout: float = 120):
        self.url, self.pos, self.timeout = url, 0, timeout
        head = urllib.request.urlopen(urllib.request.Request(url, method="HEAD"), timeout=timeout)
        self.size = int(head.headers["Content-Length"])

    def seekable(self) -> bool:
        return True

    def readable(self) -> bool:
        return True

    def tell(self) -> int:
        return self.pos

    def seek(self, offset: int, whence: int = 0) -> int:
        self.pos = {0: offset, 1: self.pos + offset, 2: self.size + offset}[whence]
        return self.pos

    def readinto(self, buffer) -> int:
        n = min(len(buffer), self.size - self.pos)
        if n <= 0:
            return 0
        request = urllib.request.Request(self.url, headers={"Range": f"bytes={self.pos}-{self.pos + n - 1}"})
        data = urllib.request.urlopen(request, timeout=self.timeout).read()
        buffer[:len(data)] = data
        self.pos += len(data)
        return len(data)


def open_remote_zip(url: str) -> zipfile.ZipFile:
    return zipfile.ZipFile(io.BufferedReader(HttpFile(url), buffer_size=1 << 20))


def fetch_member(url: str, member: str, dest: Path) -> Path:
    """Download one member of a remote zip to ``dest`` (via a temporary file)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    partial = dest.with_suffix(dest.suffix + ".part")
    with open_remote_zip(url).open(member) as src, open(partial, "wb") as out:
        shutil.copyfileobj(src, out, length=8 << 20)
    partial.rename(dest)
    return dest
