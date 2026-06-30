/-
  FedCloud Formal Verification Gateway
  Top-Level Verification Orchestrator

  This module ties together all four security cluster invariants and provides
  a unified entry point for running the complete verification suite against
  a given system state. The orchestrator collects results from each cluster
  and produces a VerificationReceipt.

  Pipeline Position:
    JSON state → Python translator → Lean types → [THIS MODULE] → receipt → OSCAL
-/

import FedCloud.BaseModel
import FedCloud.Invariants.Identity
import FedCloud.Invariants.Crypto
import FedCloud.Invariants.Architecture
import FedCloud.Invariants.Monitoring

namespace FedCloud.Verify

open FedCloud
open FedCloud.Invariants

-- ============================================================================
-- Unified System State
-- ============================================================================

/-- The complete system state aggregating all four security cluster inputs. -/
structure SystemState where
  security_context : SecurityContext
  infrastructure : InfrastructureState
  topology : ClusterTopology
  logging : LoggingFabric
  deriving Repr

-- ============================================================================
-- Full Verification Pipeline
-- ============================================================================

/--
  Run all four invariant checks against a complete system state.
  Returns a VerificationReceipt with per-cluster results.
-/
def verifyAll (state : SystemState) (timestamp : String) : VerificationReceipt :=
  { identity_status := Identity.checkIdentityInvariant state.security_context
    crypto_status := Crypto.checkCryptoInvariant state.infrastructure
    architecture_status := Architecture.checkArchitectureInvariant state.topology
    monitoring_status := Monitoring.checkMonitoringInvariant state.logging
    timestamp := timestamp }

-- ============================================================================
-- Sample Compliant State (All Invariants Pass)
-- ============================================================================

/-- A sample system state where all invariants hold. -/
def sampleCompliantState : SystemState :=
  { security_context :=
      { active_sessions :=
          [ { user_id := "admin-001"
              is_privileged := true
              has_phishing_resistant_mfa := true
              token_lifetime_minutes := 30 }
          , { user_id := "dev-042"
              is_privileged := false
              has_phishing_resistant_mfa := true
              token_lifetime_minutes := 480 }
          ] }
    infrastructure :=
      { deployed_stores :=
          [ { id := "rds-prod-main"
              contains_federal_data := true
              is_encrypted_at_rest := true
              cryptographic_module_standard := "FIPS-140-3" }
          , { id := "s3-audit-logs"
              contains_federal_data := true
              is_encrypted_at_rest := true
              cryptographic_module_standard := "FIPS-140-3" }
          , { id := "elasticache-session"
              contains_federal_data := false
              is_encrypted_at_rest := true
              cryptographic_module_standard := "AES-256" }
          ] }
    topology :=
      { nodes :=
          [ { id := "eks-node-a1"
              immutable_image_signature_valid := true
              allows_interactive_shell_access := false
              network_ingress_anywhere := false }
          , { id := "fargate-task-verify"
              immutable_image_signature_valid := true
              allows_interactive_shell_access := false
              network_ingress_anywhere := false }
          ] }
    logging :=
      { streams :=
          [ { source_id := "cloudtrail-main"
              is_actively_streaming := true
              destination_is_tamper_evident := true
              retention_days := 730 }
          , { source_id := "vpc-flow-logs"
              is_actively_streaming := true
              destination_is_tamper_evident := true
              retention_days := 365 }
          ] } }

-- ============================================================================
-- Sample Violating State (Multiple Invariants Fail)
-- ============================================================================

/-- A sample system state where multiple invariants are violated. -/
def sampleViolatingState : SystemState :=
  { security_context :=
      { active_sessions :=
          [ { user_id := "admin-rogue"
              is_privileged := true
              has_phishing_resistant_mfa := false   -- VIOLATION: no MFA
              token_lifetime_minutes := 120 }       -- VIOLATION: exceeds 60min
          ] }
    infrastructure :=
      { deployed_stores :=
          [ { id := "rds-legacy-db"
              contains_federal_data := true
              is_encrypted_at_rest := false          -- VIOLATION: unencrypted
              cryptographic_module_standard := "NONE" }
          ] }
    topology :=
      { nodes :=
          [ { id := "ec2-bastion"
              immutable_image_signature_valid := false   -- VIOLATION: unsigned image
              allows_interactive_shell_access := true    -- VIOLATION: SSH open
              network_ingress_anywhere := true }         -- VIOLATION: 0.0.0.0/0
          ] }
    logging :=
      { streams :=
          [ { source_id := "app-logs"
              is_actively_streaming := false              -- VIOLATION: not streaming
              destination_is_tamper_evident := false      -- VIOLATION: mutable target
              retention_days := 90 }                     -- VIOLATION: < 365 days
          ] } }

-- ============================================================================
-- Verification Entry Points
-- ============================================================================

/-- Verify the sample compliant state and confirm all checks pass. -/
def runCompliantCheck : VerificationReceipt :=
  verifyAll sampleCompliantState "2026-06-29T00:00:00Z"

/-- Verify the sample violating state and confirm violations are detected. -/
def runViolatingCheck : VerificationReceipt :=
  verifyAll sampleViolatingState "2026-06-29T00:00:00Z"

#eval runCompliantCheck
#eval runViolatingCheck

-- ============================================================================
-- Correctness Properties
-- ============================================================================

/-- The compliant state should produce a receipt where all clusters pass. -/
theorem compliant_state_all_verified :
  (verifyAll sampleCompliantState "test").allVerified = true := by
  native_decide

/-- The violating state should produce a receipt where not all clusters pass. -/
theorem violating_state_not_all_verified :
  (verifyAll sampleViolatingState "test").allVerified = false := by
  native_decide

end FedCloud.Verify
