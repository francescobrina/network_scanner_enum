# PortDrift product research and user-validation plan — October 2026

**Status:** opportunity hypotheses, not proven unmet needs. No claims about sales, downloads, market share or guaranteed sponsorship eligibility.

## Current competitive landscape

| Project / resource | Verified current capability | PortDrift design consequence |
| --- | --- | --- |
| [Nmap Ndiff](https://nmap.org/ndiff/) | Compares two Nmap XML scans for host, service, port and script changes | Never claim that scan diff itself is novel. |
| [NetAlertX](https://github.com/netalertx/NetAlertX) | Continuous network asset discovery, drift and alerts; multi-site integrations | Avoid duplicating a large network monitoring stack. |
| [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) | Mature scanner findings aggregation, deduplication and remediation triage | Do not attempt to recreate enterprise vulnerability management. |
| [CISA Internet Exposure Reduction](https://www.cisa.gov/resources-tools/resources/exposure-reduction) | Guidance to discover, evaluate, reduce and verify network exposure | Build a focused, evidence-to-action workflow for small IT teams. |
| [FIRST EPSS](https://www.first.org/epss/) | Public CVE exploitation probability and daily API/CSV | Only enrich **confirmed CVE IDs**; a detected TCP port alone does not establish a CVE. |
| [OWASP MCP Top 10](https://owasp.org/projects/mcp-top-10) | AI agent protocol risks: tool poisoning, secrets, authorization, oversharing | Explore a bounded read-only check of local AI endpoint security settings. |
| [LM Studio server settings](https://lmstudio.ai/docs/developer/core/server/settings) | Server bind, token authentication and MCP permissions | An explicit local-server security checklist could have practical value. |

## Product positioning hypothesis

**PortDrift = privacy-first evidence-to-action tool for administrators of small systems, home labs, and self-hosted local AI.**

Core workflow: **import authorized evidence → identify changes → record significance and confidence → assign a follow-up → verify a fix with a second scan**.

Not intended to supplant Nmap, Ndiff, NetAlertX, or DefectDojo.

## Feature priorities

### P0: Ship a trustworthy, testable mobile review interface
- Implement installable PWA app shell, sanitize user inputs and prevent CSV formula injection.
- Test installation and offline re-opening on a real Android device over HTTPS.
- Host a **fictional-data-only demo** without receiving private scan data.
- Record issues based on actual tests, not speculative metrics.

### P1: Small-team remediation workflow (next development sprint)
- Allow users to attach a local note, follow-up owner and resolution status to each evidence item.
- Explicitly distinguish "new observed port" from "vulnerability".
- Produce a follow-up export with original and verification timestamps.
- Support multiple snapshots of one authorized asset without assuming a missing observation means closure.
- Add an accessible one-screen summary for mobile use.

### P2: Local AI server exposure audit (exploratory)
- Explicit target authorization; support `localhost`, LAN and Tailscale addresses selected by the user.
- **Read-only** detection of local AI API endpoint reachability and declared security settings when data can be obtained legitimately.
- Checklist for bind address, authentication, TLS/reverse proxy, exposure scope, and MCP tool permissions.
- Do not send credentials to a cloud model; never bypass authentication or infer security configuration without evidence.
- Make no claim that an endpoint with no authentication is externally exposed merely because localhost responds.
- Begin with **LM Studio**; investigate Ollama later only if testers need it.

### P3: Evidence-aware vulnerability enrichment
- Enrich imported, explicitly known CVE IDs with CISA KEV and FIRST EPSS.
- Do not map CVEs from port/service guesses. Track provenance and publication date of each enrichment.
- Present EPSS as a 30-day estimate, not a complete risk score.

## User validation: evidence before features

Conduct at least **three legitimate pilot tests**:
1. Home lab maintainer: compare two Nmap snapshots and identify a configuration change.
2. Small IT technician: import results and create a documented follow-up for a newly observed service.
3. Local AI user: audit and document LM Studio network exposure and authentication.

For each: note user role (with permission), whether they completed the task, time to complete, confusing moments, reported bugs, voluntary GitHub issues/PRs and willingness to reuse. Do **not** fabricate GitHub stars, downloads or user testimonials. Avoid collecting public IP addresses, credentials or personal scan files.

## 30-day decision gate

Continue the chosen specialization only if real testers can complete the core task and at least two independently identify its value compared with their current tooling. If not, pivot toward improving documentation/integrations or contributing upstream to an established project.

The Codex for Open Source application should describe demonstrated maintenance and verifiable activity, with no guarantee of ChatGPT Pro.
