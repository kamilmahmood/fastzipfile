import zipfile

import _zipdecrypter


__all__ = ["monkeypatch"]


class FastZipExtFile(zipfile.ZipExtFile):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _read2(self, n):
        """
        Read n bytes from file and decrypt.
        
        Copied from _zipfile.ZipExtFile._read2
        This method adheres to new interface of _zipfile._ZipDecrypter because interface of
        _zipfile._ZipDecrypter changed by commit no 06e522521c06671b4559eecf9e2a185c2d62c141
        in bpo-10030.

        Old interface of decrypter accepts one int at time while new interface accepts bytes object
        """

        if self._compress_left <= 0:
            return b''

        n = max(n, self.MIN_READ_SIZE)
        n = min(n, self._compress_left)

        data = self._fileobj.read(n)
        self._compress_left -= len(data)
        if not data:
            raise EOFError

        if self._decrypter is not None:
            data = self._decrypter.decrypt_bytes(data)
        return data


def monkeypatch():
    zipfile.ZipExtFile = FastZipExtFile
    zipfile._ZipDecrypter = _zipdecrypter.StandardZipDecrypter


monkeypatch()
