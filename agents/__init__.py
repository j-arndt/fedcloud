"""
FedCloud Hybrid Verification Gateway — Agent Module

Provides the qualitative compliance verification engine powered by
Amazon Bedrock. Routes non-deterministic controls (personnel, training,
incident response, recovery, supply chain) through LLM agents with
RAG grounding and strict JSON schema enforcement.

Architecture:
  EventBridge/S3 → Lambda Handler → Router → Bedrock Agents → OSCAL Assembler
"""

__version__ = "0.2.0"
