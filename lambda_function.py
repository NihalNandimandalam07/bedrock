import boto3
import json
import os
import re

from botocore.exceptions import ClientError

# Bedrock client
bedrock = boto3.client("bedrock-runtime")

# Model ID
MODEL_ID = os.environ["BEDROCK_MODEL_ID"]


def clean_policy(policy):
    """
    Remove Markdown formatting if Bedrock
    returns code inside code fences.
    """

    policy = policy.strip()

    policy = re.sub(
         r"^```(?:rego)?\s*",
         "",
         policy,
         flags=re.IGNORECASE
     )

    policy = re.sub(r"\s*```$", "", policy)

    return policy.strip()


def lambda_handler(event, context):

    # Step 1: Get security requirement
    requirement = event.get("requirement")

    if not isinstance(requirement, str) or not requirement.strip():
        return {
            "statusCode": 400,
            "body": json.dumps({
                "error": "Security requirement is required"
            })
        }

    if len(requirement) > 4000:
        return {
            "statusCode": 400,
            "body": json.dumps({
            "error": "Requirement exceeds 4000 characters"
            })
        }

    # Step 2: Construct prompt
    prompt = f"""
You are an expert AWS Security and DevSecOps Engineer.

Your task is to generate Open Policy Agent
security policies using Rego.

Generate a policy based on the following
security requirement:

{requirement}

Requirements:

1. Use Rego v1 syntax.
2. Use package terraform.security.
3. Include import rego.v1.
4. Evaluate Terraform plan JSON.
5. Use input.resource_changes when applicable.
6. Create deny rules for noncompliant resources.
7. Include resource names or addresses in violations.
8. Support create and update operations.
9. Include IPv4 and IPv6 if relevant.
10. Do not invent Terraform resource attributes.
11. Do not assume unknown planned values are safe.
12. Generate only Rego code.
13. Do not include explanations or Markdown.

Return only the Rego policy.
"""

    try:

        # Step 3: Invoke Amazon Bedrock
        response = bedrock.converse(
            modelId=MODEL_ID,

            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "text": prompt
                        }
                    ]
                }
            ],

            inferenceConfig={
                "maxTokens": 4096
            }
        )

        # Step 4: Check response status
        if response.get("stopReason") != "end_turn":
            raise ValueError(
                "Bedrock did not complete generation"
            )

        # Step 5: Extract generated code
        generated_policy = "".join(
            block.get("text", "")
            for block in response["output"]["message"]["content"]
        )

        # Step 6: Clean generated Rego
        generated_policy = clean_policy(
            generated_policy
        )

        if not generated_policy:
            raise ValueError("Empty policy returned")

        # Step 7: Basic structural checks
        if (
            "package terraform.security" not in generated_policy
            or "import rego.v1" not in generated_policy
            or "deny" not in generated_policy
        ):
            raise ValueError(
                "Unexpected Rego policy structure"
            )

        # Step 8: Return generated policy
        return {
            "statusCode": 200,

            "body": json.dumps({
                "message": "OPA policy generated successfully",
                "requirement": requirement,
                "policy": generated_policy,
                "validated": False
            })
        }

    except (ClientError, ValueError, KeyError) as error:

        return {
            "statusCode": 500,

            "body": json.dumps({
                "error": "Policy generation failed",
                "error_type": type(error).__name__,
                "details": str(error)
            })
        }