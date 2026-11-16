# Third party notices

The Windows package uses CPython 3.12.14, PySide6 Essentials and Shiboken6 6.8.3, PyYAML, jsonschema and its dependencies, and the PyInstaller bootloader. Upstream versions and wheel hashes are in the lock file. Build-time icon generation uses Pillow.

- CPython uses the Python Software Foundation License. The runtime license is bundled in `licenses`.
- Qt, PySide6 and Shiboken are available under LGPLv3 and other upstream terms. This package uses dynamic Qt DLLs from the unmodified upstream distribution. License texts from the wheels are included with the runtime. Users can replace compatible dynamically loaded Qt libraries where permitted by their licenses. Source is available from the [Qt for Python project](https://code.qt.io/cgit/pyside/pyside-setup.git/tag/?h=v6.8.3) and [Qt source archives](https://download.qt.io/archive/qt/6.8/6.8.3/single/).
- PyInstaller uses GPL with a bootloader exception. See the bundled license and [upstream terms](https://pyinstaller.org/en/stable/license.html).
- PyYAML, jsonschema, and transitive dependencies retain the copyright notices and licenses from their wheels, collected under `licenses`.

The synthetic fixtures are project-authored. OWASP crAPI is a reference for the kinds of ordinary API artifacts used in application security education. The automated suite uses project-owned loopback fixtures. [OWASP crAPI](https://vwad.owasp.org/app/crapi/)
