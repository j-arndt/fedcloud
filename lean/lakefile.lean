import Lake
open Lake DSL

package fedcloud where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]

@[default_target]
lean_lib FedCloud where
  srcDir := "."
  globs := #[.submodules `FedCloud]
