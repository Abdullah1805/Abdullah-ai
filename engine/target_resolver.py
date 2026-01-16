CRITICAL_ACTIONS = [
    "iam:*",
    "organizations:*",
    "sts:AssumeRole",
    "iam:CreatePolicyVersion",
]

def classify_role(policy_engine):
    if policy_engine.allows("*", "*"):
        return "Tier-1"

    for act in CRITICAL_ACTIONS:
        if policy_engine.allows(act):
            return "Tier-1"

    if policy_engine.allows("iam:PassRole"):
        return "Tier-2"

    return "Tier-3"
