import boto3

class ManagedPolicyResolver:
    def __init__(self):
        self.client = boto3.client("iam")
        self.cache = {}

    def fetch(self, arn):
        if arn in self.cache:
            return self.cache[arn]

        policy = self.client.get_policy(PolicyArn=arn)
        version = policy["Policy"]["DefaultVersionId"]
        doc = self.client.get_policy_version(
            PolicyArn=arn,
            VersionId=version
        )["PolicyVersion"]["Document"]

        self.cache[arn] = doc
        return doc
