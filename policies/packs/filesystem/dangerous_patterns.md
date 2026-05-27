# Filesystem Dangerous Patterns

Review filesystem requests that include:

- Parent-directory traversal with `../`.
- Home-directory secrets such as `~/.ssh`, `.env`, and cloud credentials.
- System paths such as `/etc/passwd`.
- Deletes of directories or broad globs.
- Writes outside the approved workspace root.
