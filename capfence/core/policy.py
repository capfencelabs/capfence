"""Policy-as-code Engine.

YAML-based policy engine supporting capabilities, risk levels, and contextual conditions.
"""

from __future__ import annotations

import copy
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml  # type: ignore

from capfence.errors import PolicyLoadError

logger = logging.getLogger(__name__)

_KNOWN_TOP_LEVEL_KEYS = {
    "deny",
    "require_approval",
    "allow",
    "risk_levels",
    "approval_timeout_seconds",
    "extends",
    "version",
    "policy_name",
    "description",
    "enforcement_mode",
    "rules",
}

_KNOWN_CONDITION_KEYS = {
    "contains",
    "amount_gt",
    "amount_gte",
    "amount_lt",
    "amount_lte",
    "path_prefix",
    "environment",
    "user_role",
    "tenant",
    "table",
    "tool_name",
    "risk_level",
    "caller_depth_gt",
    "caller_depth_gte",
    "caller_depth_lt",
    "caller_depth_lte",
    "match_keywords",
    "match_regex",
}

_KNOWN_LEGACY_RULE_KEYS = {
    "id",
    "description",
    "capability",
    "match_keywords",
    "match_regex",
    "threshold",
    "action",
}


@dataclass
class Rule:
    capability: str
    action: str  # "allow", "deny", "require_approval", "warn"
    conditions: dict[str, Any] = field(default_factory=dict)

    def matches(self, capability: str, context: dict[str, Any], payload: dict[str, Any] | None = None) -> bool:
        from capfence.core.capabilities import Capability
        try:
            self_cap = Capability.parse(self.capability)
            req_cap = Capability.parse(capability)
            if not self_cap.matches(req_cap):
                return False
        except Exception:
            if self.capability != "*" and self.capability != capability:
                if self.capability.endswith(".*"):
                    prefix = self.capability[:-2]
                    if not capability.startswith(prefix):
                        return False
                else:
                    return False

        payload_dict = payload or {}
        payload_text = str(payload_dict).lower()
        payload_values_text = " ".join(str(value) for value in payload_dict.values())
        # Evaluate conditions
        for k, v in self.conditions.items():
            if k == "match_keywords":
                keywords = v if isinstance(v, list) else [v]
                if not any(str(keyword).lower() in payload_text for keyword in keywords):
                    return False
            elif k == "match_regex":
                patterns = v if isinstance(v, list) else [v]
                if not any(re.search(str(pattern), payload_values_text) for pattern in patterns):
                    return False
            elif k == "contains":
                if str(v).lower() not in payload_text:
                    return False
            elif k == "amount_gt":
                amount = self._extract_amount(payload_dict)
                if amount is None or amount <= v:
                    return False
            elif k == "amount_gte":
                amount = self._extract_amount(payload_dict)
                if amount is None or amount < v:
                    return False
            elif k == "amount_lt":
                amount = self._extract_amount(payload_dict)
                if amount is None or amount >= v:
                    return False
            elif k == "amount_lte":
                amount = self._extract_amount(payload_dict)
                if amount is None or amount > v:
                    return False
            elif k == "path_prefix":
                path = self._extract_path(payload_dict)
                if path is None or not path.startswith(str(v)):
                    return False
            elif k == "caller_depth_gt":
                depth = self._extract_number(context, "caller_depth")
                if depth is None or depth <= v:
                    return False
            elif k == "caller_depth_gte":
                depth = self._extract_number(context, "caller_depth")
                if depth is None or depth < v:
                    return False
            elif k == "caller_depth_lt":
                depth = self._extract_number(context, "caller_depth")
                if depth is None or depth >= v:
                    return False
            elif k == "caller_depth_lte":
                depth = self._extract_number(context, "caller_depth")
                if depth is None or depth > v:
                    return False
            else:
                # Direct context or payload match.
                if context.get(k) != v and payload_dict.get(k) != v:
                    return False
        return True

    def _extract_amount(self, payload: dict[str, Any]) -> float | None:
        for key in ("amount", "total", "value", "sum", "quantity", "price", "cost"):
            val = payload.get(key)
            if val is not None:
                try:
                    return float(val)
                except (TypeError, ValueError):
                    continue
        return None

    def _extract_path(self, payload: dict[str, Any]) -> str | None:
        for key in ("path", "file", "filepath", "filename", "target", "directory", "root"):
            val = payload.get(key)
            if val is not None:
                return str(val)
        return None

    def _extract_number(self, context: dict[str, Any], key: str) -> float | None:
        val = context.get(key)
        if val is None:
            return None
        try:
            return float(val)
        except (TypeError, ValueError):
            return None


class Policy:
    """A loaded and parsed policy."""

    def __init__(self, raw_data: dict[str, Any], policy_id: str = "default") -> None:
        self.id = policy_id
        self.raw_data = raw_data
        self.rules: list[Rule] = []
        self.risk_levels: dict[str, str] = {}
        self.validate(raw_data, policy_id)
        self._parse()

    @staticmethod
    def validate(raw_data: dict[str, Any], policy_id: str = "default") -> None:
        """Validate policy structure before use."""
        if not isinstance(raw_data, dict):
            raise PolicyLoadError(f"Policy '{policy_id}' must be a YAML mapping.")

        unknown_keys = sorted(set(raw_data) - _KNOWN_TOP_LEVEL_KEYS)
        if unknown_keys:
            raise PolicyLoadError(
                f"Policy '{policy_id}' contains unknown top-level keys: {', '.join(unknown_keys)}"
            )

        for section in ("deny", "require_approval", "allow"):
            rules = raw_data.get(section, [])
            if rules is None:
                continue
            if not isinstance(rules, list):
                raise PolicyLoadError(f"Policy '{policy_id}' section '{section}' must be a list.")
            for idx, item in enumerate(rules):
                if isinstance(item, str):
                    continue
                if not isinstance(item, dict):
                    raise PolicyLoadError(
                        f"Policy '{policy_id}' rule '{section}[{idx}]' must be a mapping or a string."
                    )
                if not item.get("capability"):
                    raise PolicyLoadError(
                        f"Policy '{policy_id}' rule '{section}[{idx}]' requires capability."
                    )
                unknown_conditions = sorted(set(item) - {"capability"} - _KNOWN_CONDITION_KEYS)
                if unknown_conditions:
                    raise PolicyLoadError(
                        f"Policy '{policy_id}' rule '{section}[{idx}]' contains unknown "
                        f"condition(s): {', '.join(unknown_conditions)}"
                    )

        legacy_rules = raw_data.get("rules", [])
        if legacy_rules is None:
            legacy_rules = []
        if not isinstance(legacy_rules, list):
            raise PolicyLoadError(f"Policy '{policy_id}' section 'rules' must be a list.")
        for idx, item in enumerate(legacy_rules):
            if not isinstance(item, dict):
                raise PolicyLoadError(f"Policy '{policy_id}' rule 'rules[{idx}]' must be a mapping.")
            if "action" not in item:
                raise PolicyLoadError(f"Policy '{policy_id}' rule 'rules[{idx}]' requires action.")
            if item["action"] not in {"allow", "deny", "block", "require_approval", "warn"}:
                raise PolicyLoadError(
                    f"Policy '{policy_id}' rule 'rules[{idx}]' has unsupported action "
                    f"'{item['action']}'."
                )
            unknown_legacy_keys = sorted(set(item) - _KNOWN_LEGACY_RULE_KEYS)
            if unknown_legacy_keys:
                raise PolicyLoadError(
                    f"Policy '{policy_id}' rule 'rules[{idx}]' contains unknown "
                    f"key(s): {', '.join(unknown_legacy_keys)}"
                )

        risk_levels = raw_data.get("risk_levels", {})
        if risk_levels is not None and not isinstance(risk_levels, dict):
            raise PolicyLoadError(f"Policy '{policy_id}' risk_levels must be a mapping.")
        for level, config in (risk_levels or {}).items():
            if not isinstance(config, dict) or "action" not in config:
                raise PolicyLoadError(
                    f"Policy '{policy_id}' risk level '{level}' must define an action."
                )
            if config["action"] not in {"allow", "deny", "block", "require_approval", "warn"}:
                raise PolicyLoadError(
                    f"Policy '{policy_id}' risk level '{level}' has unsupported action "
                    f"'{config['action']}'."
                )

    def _parse(self) -> None:
        # Parse the legacy rules schema used by bundled starter policies.
        for item in self.raw_data.get("rules", []):
            if isinstance(item, dict) and "action" in item:
                conditions = {
                    k: v
                    for k, v in item.items()
                    if k in {"match_keywords", "match_regex"}
                }
                self.rules.append(
                    Rule(
                        capability=item.get("capability", "*"),
                        action=item["action"],
                        conditions=conditions,
                    )
                )

        # Parse deny
        for item in self.raw_data.get("deny", []):
            if isinstance(item, str):
                self.rules.append(Rule(capability=item, action="deny"))
            elif isinstance(item, dict) and "capability" in item:
                conditions = {k: v for k, v in item.items() if k != "capability"}
                self.rules.append(Rule(capability=item["capability"], action="deny", conditions=conditions))
        
        # Parse require_approval
        for item in self.raw_data.get("require_approval", []):
            if isinstance(item, str):
                self.rules.append(Rule(capability=item, action="require_approval"))
            elif isinstance(item, dict) and "capability" in item:
                conditions = {k: v for k, v in item.items() if k != "capability"}
                self.rules.append(Rule(capability=item["capability"], action="require_approval", conditions=conditions))

        # Parse allow
        for item in self.raw_data.get("allow", []):
            if isinstance(item, str):
                self.rules.append(Rule(capability=item, action="allow"))
            elif isinstance(item, dict) and "capability" in item:
                conditions = {k: v for k, v in item.items() if k != "capability"}
                self.rules.append(Rule(capability=item["capability"], action="allow", conditions=conditions))

        # Parse risk_levels
        rl = self.raw_data.get("risk_levels", {})
        for level, config in rl.items():
            if isinstance(config, dict) and "action" in config:
                self.risk_levels[level] = config["action"]

    def merge(self, other: Policy) -> None:
        """Merge another policy into this one (layering)."""
        # other policy takes precedence
        self.rules = other.rules + self.rules
        self.risk_levels.update(other.risk_levels)
        # Deep merge raw_data for audit purposes
        self.raw_data.update(copy.deepcopy(other.raw_data))

    def evaluate(self, capability: str, context: dict[str, Any], payload: dict[str, Any] | None = None) -> str | None:
        """Evaluate rules and return action if matched. Evaluates in order."""
        for rule in self.rules:
            if rule.matches(capability, context, payload):
                return rule.action
        return None

    def has_capability_rule(self, capability: str) -> bool:
        """Return True when any rule names this capability or a matching wildcard prefix."""
        for rule in self.rules:
            if rule.capability == capability:
                return True
            if rule.capability.endswith(".*") and capability.startswith(rule.capability[:-2]):
                return True
        return False

    def evaluate_risk_level(self, risk_level: str) -> str | None:
        """Evaluate action based on risk level."""
        return self.risk_levels.get(risk_level)


class PolicyLoader:
    """Loads and merges YAML policies."""

    def __init__(self, search_paths: list[str | Path] | None = None) -> None:
        self.search_paths = [Path(p) for p in (search_paths or [])]
        self._cache: dict[str, Policy] = {}

    def load(self, path: str | Path) -> Policy:
        path_str = str(path)
        if path_str in self._cache:
            return self._cache[path_str]

        file_path = Path(path)
        if not file_path.is_absolute():
            # Search in search_paths
            for sp in self.search_paths:
                candidate = sp / file_path
                if candidate.exists():
                    file_path = candidate
                    break

        if not file_path.exists():
            raise PolicyLoadError(f"Policy file not found: {file_path}")

        with open(file_path, "r", encoding="utf-8") as f:
            try:
                data = yaml.safe_load(f) or {}
            except yaml.YAMLError as exc:
                raise PolicyLoadError(f"Policy file is not valid YAML: {file_path}") from exc

        policy = Policy(data, policy_id=file_path.stem)
        
        # Check for inheritance/composition (e.g. `extends: "base.yaml"`)
        extends = data.get("extends")
        if extends:
            if isinstance(extends, str):
                extends = [extends]
            
            base_policy = Policy({}, policy_id="merged")
            for base_path in extends:
                parent = self.load(base_path)
                base_policy.merge(parent)
            
            base_policy.merge(policy)
            policy = base_policy
            policy.id = file_path.stem

        self._cache[path_str] = policy
        return policy
