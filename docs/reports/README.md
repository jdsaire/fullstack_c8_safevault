# SafeVault · Activity Completion Reports

This directory serves as the repository archive for **Activity Completion Reports** across all development cycles of the SafeVault capstone project (Microsoft Full Stack Developer Specialization — Course 8: *Security and Authentication*).

---

## Purpose & Delivery Workflow

In alignment with repository engineering standards:
1. **Branch & Pull Request Delivery**: Every Activity Completion Report and report update is committed on a dedicated activity or review branch and delivered through a Pull Request reviewed and merged by `jdsaire`. Reports are never committed directly to `main`.
2. **Architecture & Evolution Record**: Each report documents the architectural decisions, iterative refinements, and technical debugging steps verified in the codebase.
3. **Evidence Provenance (`[M]` vs. `[SIM]`)**: Every report cross-references commit SHAs, pull requests, and automated `.NET 8` / NUnit test outputs, explicitly separating measured execution (`[M]`) from simulated attack payloads or browser fallback behavior (`[SIM]`).

---

## Report Schema Standard

Each Activity Completion Report follows a consistent nine-section structure:
- **1. Executive Summary**: Overview of objectives, outcomes, and milestone deliverables.
- **2. Course 8 Capstone Rubric Alignment**: Verbatim mapping against the six Course 8 capstone rubric criteria (`C1` through `C6`, 5 points each) without self-awarded scores.
- **3. Chronological Evolution & Iteration History**: Progression of commits and pull requests across the activity.
- **4. Technical Debugging Deep Dive & Root Cause Analysis**: Root cause analysis and verification of defects resolved during the activity (`[M]` vs. `[SIM]`).
- **5. Security Telemetry & Automated Test Suite Audit**: Measured NUnit console output (`[M]`) and attack vector coverage tables.
- **6. Component Architecture**: Breakdown of backend services, data repositories, test fixtures, and frontend workspaces.
- **7. Scope Boundaries**: Explicit demarcation between the completed activity and subsequent capstone activities.
- **8. Artifact & Verification Audit Ledger**: Audit ledger of commits, pull requests, build/test verifications (`[M]`), and interactive demo surfaces (`[SIM]`).
- **9. Author & AI Assistance Disclosure Attestation**: Sole authorship attestation (`jdsaire`) and generic disclosure of how an AI environment assisted during the activity.

---

## Activity Reports Index

| Activity ID | Title | Code Status | Pull Requests | Author | Date | Report Link |
|---|---|---|---|---|---|---|
| **C8-ACT1** | Input Validation, Parameterized Queries & Multipage Architecture | Completed on `main` (`eb99ab5`) | [#1](https://github.com/jdsaire/fullstack_c8_safevault/pull/1), [#2](https://github.com/jdsaire/fullstack_c8_safevault/pull/2), [#3](https://github.com/jdsaire/fullstack_c8_safevault/pull/3) | Juan Diego S. | Nov 2026 | [ACTIVITY-1-COMPLETION-REPORT.md](ACTIVITY-1-COMPLETION-REPORT.md) |
| **C8-ACT2** | Authentication & Role-Based Access Control (RBAC) | Completed on `main` (`feedc6a`) | [#4](https://github.com/jdsaire/fullstack_c8_safevault/pull/4) | Juan Diego S. | Nov 2026 | [ACTIVITY-2-COMPLETION-REPORT.md](ACTIVITY-2-COMPLETION-REPORT.md) |
| **C8-ACT3** | Security Debugging, Vulnerability Remediation & Capstone Summary | Code completed on `main` (`52227f2`) | [#5](https://github.com/jdsaire/fullstack_c8_safevault/pull/5) | Juan Diego S. | Nov 2026 | *Report pending next run* |
