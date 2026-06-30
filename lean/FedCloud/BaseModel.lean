/-
  FedCloud Formal Verification Gateway
  Base Model — Shared Type Definitions

  This module defines the core data structures that represent cloud infrastructure
  state, identity contexts, and compliance metadata. All invariant theorems across
  the four security clusters operate on these types.

  Architecture:
    AWS/Azure/GCP telemetry → JSON → Python translator → these Lean types → proof kernel
-/

namespace FedCloud

-- ============================================================================
-- Identity and Access Management Types
-- ============================================================================

/-- Represents an active authenticated session within the identity perimeter. -/
structure Session where
  user_id : String
  is_privileged : Bool
  has_phishing_resistant_mfa : Bool
  token_lifetime_minutes : Nat
  deriving Repr, BEq

/-- The aggregate identity security context across all active sessions. -/
structure SecurityContext where
  active_sessions : List Session
  deriving Repr

-- ============================================================================
-- System and Communications Protection Types
-- ============================================================================

/-- Represents a deployed data store (database, object store, file system). -/
structure DataStore where
  id : String
  contains_federal_data : Bool
  is_encrypted_at_rest : Bool
  cryptographic_module_standard : String  -- e.g., "FIPS-140-3"
  deriving Repr, BEq

/-- The aggregate infrastructure state for all deployed data stores. -/
structure InfrastructureState where
  deployed_stores : List DataStore
  deriving Repr

-- ============================================================================
-- Cloud Native Architecture Types
-- ============================================================================

/-- Represents a compute resource (container, VM, serverless function). -/
structure ComputeResource where
  id : String
  immutable_image_signature_valid : Bool
  allows_interactive_shell_access : Bool  -- SSH, SSM Session Manager, etc.
  network_ingress_anywhere : Bool         -- 0.0.0.0/0 open ingress
  deriving Repr, BEq

/-- The aggregate cluster topology for all production compute nodes. -/
structure ClusterTopology where
  nodes : List ComputeResource
  deriving Repr

-- ============================================================================
-- Monitoring, Logging, and Auditing Types
-- ============================================================================

/-- Represents a log stream from an infrastructure or application component. -/
structure LogStream where
  source_id : String
  is_actively_streaming : Bool
  destination_is_tamper_evident : Bool
  retention_days : Nat
  deriving Repr, BEq

/-- The aggregate logging fabric across all monitored components. -/
structure LoggingFabric where
  streams : List LogStream
  deriving Repr

-- ============================================================================
-- Verification Output Types
-- ============================================================================

/-- Result of a single invariant verification check. -/
inductive VerificationStatus where
  | verified : VerificationStatus
  | violated : String → VerificationStatus  -- carries the violation description
  deriving Repr

/-- A complete verification receipt covering all four security clusters. -/
structure VerificationReceipt where
  identity_status : VerificationStatus
  crypto_status : VerificationStatus
  architecture_status : VerificationStatus
  monitoring_status : VerificationStatus
  timestamp : String
  deriving Repr

/-- Check if all clusters passed verification. -/
def VerificationReceipt.allVerified (r : VerificationReceipt) : Bool :=
  match r.identity_status, r.crypto_status, r.architecture_status, r.monitoring_status with
  | .verified, .verified, .verified, .verified => true
  | _, _, _, _ => false

end FedCloud
