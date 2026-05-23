package capfence.authz

default result := {"verdict": "deny", "reason": "default deny"}

result := {"verdict": "deny", "reason": "destructive shell command"} if {
  input.capability == "shell.exec"
  contains(input.payload.command, "rm -rf")
} else := {"verdict": "require_approval", "reason": "privileged shell command"} if {
  input.capability == "shell.exec"
  contains(input.payload.command, "sudo")
} else := {"verdict": "allow", "reason": "read-only diagnostic"} if {
  input.capability == "shell.exec"
  regex.match("^(ls|pwd|git status)(\\\\s|$)", input.payload.command)
}
