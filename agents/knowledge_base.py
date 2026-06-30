"""
FedCloud Knowledge Base Interface

Provides RAG grounding against approved policy documents via
Amazon Bedrock Knowledge Base. In mock mode, returns excerpts
from local policy fixtures.

Production: Queries Amazon Bedrock Knowledge Base with semantic search.
Mock: Returns relevant policy excerpts from local fixtures.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from agents.config import BedrockConfig


@dataclass
class KBResult:
    """A retrieved document chunk from the knowledge base."""
    content: str
    source: str
    score: float = 0.0
    page: Optional[int] = None
    section: Optional[str] = None


class PolicyKnowledgeBase:
    """
    Interface to the RAG knowledge base containing approved
    corporate security policies and FedRAMP baseline documents.
    """

    def __init__(self, config: BedrockConfig, fixtures_dir: str = "fixtures/qualitative"):
        self.config = config
        self.fixtures_dir = Path(fixtures_dir)
        self._client = None

    def query(self, question: str, top_k: int = 3) -> list[KBResult]:
        """
        Query the knowledge base for relevant policy excerpts.

        Args:
            question: Natural language query.
            top_k: Number of results to return.

        Returns:
            List of KBResult with relevant policy text.
        """
        if self.config.knowledge_base_id:
            return self._live_query(question, top_k)
        return self._mock_query(question, top_k)

    def _live_query(self, question: str, top_k: int) -> list[KBResult]:
        """Query Amazon Bedrock Knowledge Base. Requires boto3."""
        try:
            import boto3
        except ImportError:
            raise RuntimeError("boto3 required for live KB queries")

        if self._client is None:
            self._client = boto3.client(
                "bedrock-agent-runtime",
                region_name=self.config.region,
            )

        response = self._client.retrieve(
            knowledgeBaseId=self.config.knowledge_base_id,
            retrievalQuery={"text": question},
            retrievalConfiguration={
                "vectorSearchConfiguration": {"numberOfResults": top_k}
            },
        )

        results = []
        for chunk in response.get("retrievalResults", []):
            content = chunk.get("content", {}).get("text", "")
            source = chunk.get("location", {}).get("s3Location", {}).get("uri", "unknown")
            score = chunk.get("score", 0.0)
            results.append(KBResult(content=content, source=source, score=score))

        return results

    def _mock_query(self, question: str, top_k: int) -> list[KBResult]:
        """Return mock policy excerpts from local fixtures."""
        policy_path = self.fixtures_dir / "mock_policy_excerpts.json"
        if not policy_path.exists():
            return [KBResult(
                content="All personnel with access to federal information systems must undergo "
                        "background investigations commensurate with the risk level of the position.",
                source="FedRAMP 20x Baseline Handbook",
                score=0.95,
                section="Personnel Security Requirements",
            )]

        with open(policy_path) as f:
            policies = json.load(f)

        # Simple keyword matching for mock mode
        question_lower = question.lower()
        scored = []
        for policy in policies.get("excerpts", []):
            text = policy.get("content", "").lower()
            keywords = question_lower.split()
            matches = sum(1 for kw in keywords if kw in text)
            score = matches / max(len(keywords), 1)
            scored.append((score, policy))

        scored.sort(key=lambda x: x[0], reverse=True)

        return [
            KBResult(
                content=p.get("content", ""),
                source=p.get("source", "Policy Document"),
                score=s,
                section=p.get("section"),
                page=p.get("page"),
            )
            for s, p in scored[:top_k]
        ]
