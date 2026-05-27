# Filesystem Policy Pack Tests

Minimum checks before adapting this pack:

- `read ~/.ssh/id_rsa` is denied.
- `read /etc/passwd` is denied.
- `write ../../app.py` is denied.
- `read ./workspace/report.md` is allowed.
- `write ./workspace/output.json` is allowed.
