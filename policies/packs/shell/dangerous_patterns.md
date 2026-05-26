# Shell Dangerous Patterns

CapFence policy packs are starter authorization policies for common agent side effects. They are not universal security policies. Treat them as explicit defaults to adapt, test, and review.

Review shell commands that include:

- Recursive destructive filesystem operations such as `rm -rf`.
- Direct package installation or script execution from network input.
- Reads of secrets such as `.env`, `.ssh/id_rsa`, or cloud credential files.
- Permission broadening such as `chmod -R 777`.
- Disk and filesystem operations such as `mkfs` or `dd if=`.
