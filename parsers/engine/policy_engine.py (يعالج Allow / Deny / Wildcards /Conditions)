class PolicyEngine:
    def __init__(self, policy_doc):
        self.statements = policy_doc.get("Statement", [])

    def _match(self, value, pattern):
        return pattern == "*" or value == pattern or (
            isinstance(pattern, list) and value in pattern
        )

    def allows(self, action, resource="*", context=None):
        allowed = False

        for stmt in self.statements:
            effect = stmt.get("Effect")
            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", [])

            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]

            action_match = any(
                self._match(action, a) or self._match("*", a)
                for a in actions
            )
            resource_match = any(
                self._match(resource, r) or self._match("*", r)
                for r in resources
            )

            if not action_match or not resource_match:
                continue

            # Conditions handling (basic but accurate)
            if "Condition" in stmt and context:
                for key, cond in stmt["Condition"].items():
                    for k, v in cond.items():
                        if context.get(k) != v:
                            continue

            if effect == "Deny":
                return False
            elif effect == "Allow":
                allowed = True

        return allowed
