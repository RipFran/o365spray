#!/usr/bin/env python3

from pathlib import Path
import threading


class ThreadWriter(object):

    """Custom class to write data to a file accross threads"""

    def __init__(self, file_: str, out_dir: str):
        """Initialize a ThreadWriter instance.

        Arguments:
            file_: name of file to write to
            out_dir: name of directory to write file to

        Raises:
            ValueError: if directory does not exist
        """
        if not Path(out_dir).is_dir():
            raise ValueError(f"Invalid output directory: {out_dir}")
        self.output_file = f"{out_dir}{file_}"
        # Updated: use a lock and line buffering to keep writes consistent and real-time.
        self._lock = threading.Lock()
        self.out_file = open(self.output_file, "a", buffering=1, encoding="utf-8")

    def write(self, data: str):
        """Write data to file

        Arguments:
            data: data to write to file
        """
        # Updated: lock + flush per write so output is persisted in real time.
        with self._lock:
            self.out_file.write(f"{data}\n")
            self.out_file.flush()

    def flush(self):
        """Flush the file buffer"""
        # Updated: lock around flush for thread safety.
        with self._lock:
            self.out_file.flush()

    def close(self):
        """Close the file handle"""
        # Updated: lock around close for thread safety.
        with self._lock:
            self.out_file.close()
