# fastzipfile
Read Standard Encryption 2.0 encrypted Zips 100x faster with same interface as standard library's zipfile.Zipfile

# Installation
```
pip install fastzipfile
```
# Usage
```python
from fastzipfile import FastZipFile

# There is no change in interface from zipfile.Zipfile
with FastZipFile('path-to-file.zip', mode='r') as fz:
    f = fz.open('path-to-file-in-zip', pwd=b'password')
    content = f.read()
```

# Limitation
Currently it only supports what zipfile.ZipFile supports e.g. no AES-128 or AES-256 support.

# License
This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details


