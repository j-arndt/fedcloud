"""
FedCloud AWS Lambda Handler

Entry point for the serverless verification gateway. Receives events
from EventBridge, S3, or direct API Gateway invocations. Routes to
the appropriate verification engine and returns OSCAL-compatible results.

Event sources:
  - EventBridge: AWS Config changes, CloudTrail events
  - S3: Document uploads (PDFs, training certs, SBOM files)
  - API Gateway: Direct verification requests
"""

import json
import logging
import os
from typing import Any

from agents.config import AgentConfig, BedrockConfig
from agents.router import classify_event, route_and_evaluate

logger = logging.getLogger("fedcloud-gateway")
logger.setLevel(logging.INFO)


def build_config_from_env() -> AgentConfig:
    """Build agent configuration from Lambda environment variables."""
    return AgentConfig(
        mode=os.environ.get("FEDCLOUD_MODE", "mock"),
        bedrock=BedrockConfig(
            region=os.environ.get("AWS_REGION", "us-gov-west-1"),
            model_id=os.environ.get(
                "BEDROCK_MODEL_ID",
                "anthropic.claude-3-5-sonnet-20241022-v2:0",
            ),
            max_tokens=int(os.environ.get("BEDROCK_MAX_TOKENS", "4096")),
            temperature=float(os.environ.get("BEDROCK_TEMPERATURE", "0.0")),
            knowledge_base_id=os.environ.get("BEDROCK_KB_ID"),
            guardrail_id=os.environ.get("BEDROCK_GUARDRAIL_ID"),
        ),
    )


def handler(event: dict, context: Any = None) -> dict:
    """
    AWS Lambda handler for the FedCloud verification gateway.

    Accepts events from multiple sources and routes them through
    the hybrid verification pipeline.

    Args:
        event: Lambda event payload.
        context: Lambda context object (unused in PoC).

    Returns:
        Dict with statusCode, routing decision, and evaluation results.
    """
    logger.info("Received event: %s", json.dumps(event, default=str)[:500])

    config = build_config_from_env()

    # Extract telemetry from various event source formats
    telemetry = extract_telemetry(event)

    if not telemetry:
        return {
            "statusCode": 400,
            "body": {"error": "No telemetry data found in event"},
        }

    # Route and evaluate
    try:
        result = route_and_evaluate(telemetry, config)

        logger.info(
            "Routing decision: engine=%s cluster=%s confidence=%.2f",
            result["routing"]["engine"],
            result["routing"]["cluster"],
            result["routing"]["confidence"],
        )

        return {
            "statusCode": 200,
            "body": result,
        }

    except Exception as e:
        logger.error("Verification failed: %s", str(e), exc_info=True)
        return {
            "statusCode": 500,
            "body": {"error": str(e)},
        }


def extract_telemetry(event: dict) -> dict:
    """
    Extract telemetry data from Lambda event, handling multiple source formats.

    Supports:
      - Direct payload (telemetry in event root)
      - API Gateway (telemetry in event["body"])
      - S3 notification (reference to uploaded file)
      - EventBridge (telemetry in event["detail"])
    """
    # Direct payload — most common in PoC
    if any(key in event for key in ("sessions", "databases", "compute",
           "background_checks", "training_records", "incidents",
           "sbom", "dr_exercises", "metadata")):
        return event

    # API Gateway format
    if "body" in event and isinstance(event["body"], str):
        try:
            return json.loads(event["body"])
        except json.JSONDecodeError:
            pass

    if "body" in event and isinstance(event["body"], dict):
        return event["body"]

    # EventBridge format
    if "detail" in event and "source" in event:
        detail = event["detail"]
        detail.setdefault("metadata", {})["source"] = event.get("source", "eventbridge")
        return detail

    # S3 notification format
    if "Records" in event:
        records = event["Records"]
        if records and records[0].get("eventSource") == "aws:s3":
            bucket = records[0]["s3"]["bucket"]["name"]
            key = records[0]["s3"]["object"]["key"]
            return {
                "metadata": {
                    "source": "s3",
                    "bucket": bucket,
                    "key": key,
                    "engine": "bedrock",  # S3 uploads are typically qualitative
                },
                "s3_reference": f"s3://{bucket}/{key}",
            }

    return {}


# For local testing
if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        with open(sys.argv[1]) as f:
            test_event = json.load(f)
    else:
        test_event = {
            "metadata": {"cluster": "personnel"},
            "background_checks": [
                {"employee_id": "EMP-001", "status": "cleared", "date": "2026-05-12"}
            ],
        }

    result = handler(test_event)
    print(json.dumps(result, indent=2))
