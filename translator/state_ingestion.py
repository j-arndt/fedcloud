"""
FedCloud State Ingestion Service

Polls and receives cloud state events from AWS Config, CloudTrail,
EventBridge, and application metadata APIs. In PoC mode, operates
against local mock fixtures.

Architecture:
  EventBridge / Config Rules → this service → JSON state → translator → Lean

Production mode: Subscribes to SQS queues fed by EventBridge rules.
Mock mode: Reads from local fixture files and simulates event-driven updates.
"""

import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class IngestionConfig:
    """Configuration for the state ingestion service."""
    mode: str = "mock"                      # "mock" or "live"
    fixture_dir: str = "fixtures"           # Directory for mock fixtures
    poll_interval_seconds: int = 60         # Polling interval for live mode
    aws_region: str = "us-east-1"
    sqs_queue_url: Optional[str] = None     # SQS queue for EventBridge events
    output_path: str = "state/current_state.json"


@dataclass
class StateSnapshot:
    """A point-in-time snapshot of the complete infrastructure state."""
    sessions: list = field(default_factory=list)
    databases: list = field(default_factory=list)
    compute: list = field(default_factory=list)
    log_streams: list = field(default_factory=list)
    timestamp: str = ""
    source: str = "unknown"

    def to_dict(self) -> dict:
        return {
            "sessions": self.sessions,
            "databases": self.databases,
            "compute": self.compute,
            "log_streams": self.log_streams,
            "metadata": {
                "timestamp": self.timestamp,
                "source": self.source,
            }
        }


class MockIngestionService:
    """
    Reads infrastructure state from local fixture files.
    Simulates the event-driven ingestion pipeline for PoC validation.
    """

    def __init__(self, config: IngestionConfig):
        self.config = config
        self.fixture_dir = Path(config.fixture_dir)

    def ingest_aws_topology(self) -> dict:
        """Load mock AWS infrastructure topology."""
        path = self.fixture_dir / "mock_aws_topology.json"
        if not path.exists():
            print(f"Warning: {path} not found, returning empty state")
            return {}
        with open(path) as f:
            return json.load(f)

    def ingest_terraform_plan(self) -> dict:
        """Load mock Terraform plan output."""
        path = self.fixture_dir / "mock_terraform_plan.json"
        if not path.exists():
            print(f"Warning: {path} not found, returning empty state")
            return {}
        with open(path) as f:
            return json.load(f)

    def ingest_app_metadata(self) -> dict:
        """Load mock application metadata schema."""
        path = self.fixture_dir / "mock_tyler_app_schema.json"
        if not path.exists():
            print(f"Warning: {path} not found, returning empty state")
            return {}
        with open(path) as f:
            return json.load(f)

    def build_snapshot(self) -> StateSnapshot:
        """
        Merge all fixture sources into a single StateSnapshot.
        In production, this merges live API responses.
        """
        aws = self.ingest_aws_topology()
        app = self.ingest_app_metadata()

        snapshot = StateSnapshot(
            sessions=aws.get("sessions", []) + app.get("sessions", []),
            databases=aws.get("databases", []) + app.get("databases", []),
            compute=aws.get("compute", []),
            log_streams=aws.get("log_streams", []),
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            source="mock-fixtures",
        )
        return snapshot

    def write_snapshot(self, snapshot: StateSnapshot) -> str:
        """Write the state snapshot to the configured output path."""
        output = Path(self.config.output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output, "w") as f:
            json.dump(snapshot.to_dict(), f, indent=2)
        return str(output)


class LiveIngestionService:
    """
    Production ingestion service that polls AWS APIs.
    Stub implementation for PoC — demonstrates the interface contract.
    """

    def __init__(self, config: IngestionConfig):
        self.config = config

    def poll_iam_credential_report(self) -> list:
        """Poll AWS IAM for current credential report. (Stub)"""
        raise NotImplementedError(
            "Live IAM polling requires boto3 and AWS credentials. "
            "Use mock mode for PoC validation."
        )

    def poll_config_resources(self) -> list:
        """Poll AWS Config for resource inventory. (Stub)"""
        raise NotImplementedError(
            "Live Config polling requires boto3 and AWS credentials. "
            "Use mock mode for PoC validation."
        )

    def receive_eventbridge_events(self) -> list:
        """Receive events from SQS queue fed by EventBridge. (Stub)"""
        raise NotImplementedError(
            "Live EventBridge reception requires boto3 and SQS queue URL. "
            "Use mock mode for PoC validation."
        )


def create_ingestion_service(config: IngestionConfig):
    """Factory: return the appropriate ingestion service for the configured mode."""
    if config.mode == "mock":
        return MockIngestionService(config)
    elif config.mode == "live":
        return LiveIngestionService(config)
    else:
        raise ValueError(f"Unknown ingestion mode: {config.mode}")


def main():
    """CLI entry point: run a single ingestion cycle and write the state snapshot."""
    config = IngestionConfig(
        mode="mock",
        fixture_dir=sys.argv[1] if len(sys.argv) > 1 else "fixtures",
        output_path=sys.argv[2] if len(sys.argv) > 2 else "state/current_state.json",
    )

    service = create_ingestion_service(config)
    snapshot = service.build_snapshot()
    output_path = service.write_snapshot(snapshot)
    print(f"State snapshot written to {output_path}")
    print(f"  Sessions: {len(snapshot.sessions)}")
    print(f"  Data stores: {len(snapshot.databases)}")
    print(f"  Compute nodes: {len(snapshot.compute)}")
    print(f"  Log streams: {len(snapshot.log_streams)}")


if __name__ == "__main__":
    main()
