# Credential Placement

The agent should not hold raw downstream credentials.

Recommended:

```txt
Agent
  proposes action only

CapFence
  evaluates authorization policy

Gated executor
  holds downstream credentials
  invokes tool only after allow

Downstream system
  receives only authorized calls
```

Do not deploy:

```txt
Agent -> Direct API key -> Production system
```

CapFence cannot protect direct paths it does not control.
