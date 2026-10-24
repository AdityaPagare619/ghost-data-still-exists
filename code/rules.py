"""Data-driven deletion-rule contract (Unit 3).

The 15-rule contract is READ from the dataset's deletion-rules file at
runtime. This module never copies the contract's constants into code:
the caller supplies the rules path and this module parses it into a
RuleBook. The descriptive conditions in the contract ("Always",
"still attributable", "within the supplied retention period", ...) are
interpreted by the shape tests in classify.py; this module only holds
the parsed contract and the operation vocabularies fixed by the output
schema (phases, operations, states, sort ranks).

Stdlib only. No model calls. No verdict inputs other than the rules
file, the classified lanes, and the subject's identifiers.
"""

import csv

# Output-schema vocabularies (fixed by the competition contract).
PHASE_RANK = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
FINDING_OP_RANK = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
}
REMEDIATION_OP_RANK = {
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
}
VERIFICATION_OP_RANK = {
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}
# 1:1 remediation counterpart for each finding operation.
FINDING_TO_REMEDIATION = {
    "REPORT_REMAINING_RECORD": ("DELETE_RECORD", "ABSENT"),
    "REPORT_EXPOSED_PII": None,  # REDACT vs ANONYMIZE decided by category
    "REPORT_ACTIVE_DATA_FLOW": ("DISABLE_DATA_FLOW", "DISABLED"),
    "REPORT_RESTORE_RISK": ("BLOCK_RESTORE", "BLOCKED"),
}
# Verification operation/state for a remediated resource, by remediation.
REMEDIATION_TO_VERIFICATION = {
    "DELETE_RECORD": ("VERIFY_RECORD_ABSENT", "ABSENT"),
    "REDACT_RECORD": ("VERIFY_RECORD_REDACTED", "REDACTED"),
    "ANONYMIZE_RECORD": ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
    "DISABLE_DATA_FLOW": ("VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
    "BLOCK_RESTORE": ("VERIFY_RESTORE_BLOCKED", "BLOCKED"),
}
# Categories whose exposed-identifier remediation is anonymisation.
ANONYMIZE_CATEGORIES = {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}


class RuleBook:
    """Parsed deletion-rules contract: category -> rule record."""

    def __init__(self, rules):
        # rules: dict category -> {"rule_id", "condition", "action"}
        self.rules = dict(rules)

    @classmethod
    def from_csv(cls, path):
        rules = {}
        with open(path, newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                category = (row.get("data_category") or "").strip()
                if not category:
                    continue
                rules[category] = {
                    "rule_id": (row.get("rule_id") or "").strip(),
                    "condition": (row.get("condition") or "").strip(),
                    "action": (row.get("required_action") or "").strip(),
                }
        return cls(rules)

    def action_for(self, category):
        entry = self.rules.get(category)
        return entry["action"] if entry else None

    def rule_id_for(self, category):
        entry = self.rules.get(category)
        return entry["rule_id"] if entry else None

    def categories(self):
        return sorted(self.rules)


def operation_rank(phase, operation):
    if phase == "FINDING":
        return FINDING_OP_RANK.get(operation, 99)
    if phase == "REMEDIATION":
        return REMEDIATION_OP_RANK.get(operation, 99)
    if phase == "VERIFICATION":
        return VERIFICATION_OP_RANK.get(operation, 99)
    return 99
