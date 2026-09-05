# Existing Systems / Related Work

**Author:** Person 4 (Research / Dataset)
**Priority:** Day 3
**Purpose:** Briefly review 3–4 relevant DFIR or AI-forensics systems/approaches and note how our multi-agent, evidence-grounded approach differs. For the final report's related-work section.

## 1. Timesketch (Google)

Open-source collaborative timeline analysis tool. Ingests logs from many sources (Plaso/log2timeline output, Sysmon, cloud logs) into one searchable, taggable timeline that analysts explore manually, with saved searches and simple rule-based "sigma-style" tagging to flag known-bad patterns.

- **Strength:** mature, battle-tested at scale, good UI for human analysts. It is a good example of the traditional DFIR pattern, where structured artifacts such as logs and filesystem metadata are processed by several specialized tools for evidence identification, feature extraction, and timeline building, with the human analyst doing the actual reasoning.
- **Gap vs. our approach:** no automated narrative generation or technique correlation — the analyst still has to read the timeline and connect the dots. It's a display/search layer, not a reasoning layer.

## 2. Velociraptor / GRR Rapid Response

Endpoint DFIR and live-forensics collection platforms. Both let an investigator remotely query many hosts for artifacts (processes, files, registry, network state) using pre-built "hunts"/"flows," and return structured results fast across a fleet.

- **Strength:** excellent at *collection* at scale — built for enterprise incident response, not single-host analysis.
- **Gap vs. our approach:** they retrieve evidence, but don't correlate it into a technique-labeled timeline or generate an incident narrative. Analysis is still a manual step after collection.

## 3. GenDFIR (Loumachi & Ghanem, 2024–2025)

An academic framework that pairs rule-based artifact selection with a single LLM (via Retrieval-Augmented Generation) to perform automated timeline analysis. It was evaluated on synthetic cyber incident events in a controlled setting, using DFIR-specific metrics designed to check the framework's performance and reliability, with human review used to validate the outcomes.

- **Strength:** first serious academic demonstration that an LLM+RAG pipeline can meaningfully automate timeline reconstruction, with real evaluation metrics rather than just a demo.
- **Gap vs. our approach:** GenDFIR is a **single-model RAG pipeline** — one LLM doing rule-filtered retrieval and generation, not a multi-agent system with separate roles for parsing, technique correlation, and narrative-building. It's also focused specifically on timeline analysis, not the broader parse → correlate → explain pipeline we're building.

## 4. Multi-agent LLM incident-response frameworks (IRCopilot, AutoBnB / AutoBnB-RAG)

A newer cluster of research explores multiple cooperating LLM agents for incident response rather than one model doing everything. IRCopilot organizes agents around an inference-action-reflection loop to keep long incidents from losing context; AutoBnB simulates incident-response team roles as a tabletop-exercise game, and AutoBnB-RAG adds retrieval so agents aren't limited to what's in their prompt.

- **Strength:** validates the core idea behind our project — splitting DFIR reasoning across specialized agents avoids the context-window and "one model tries to do everything" problems that pure single-LLM approaches like GenDFIR run into.
- **Gap vs. our approach:** these frameworks are largely oriented toward *simulating/coordinating human response actions and decision-making* (playbooks, team roles, what to do next), rather than *grounding each output in specific parsed evidence and a matched MITRE technique* the way our pipeline aims to.

## How our approach differs, overall

| | Timesketch / Velociraptor-GRR | GenDFIR | IRCopilot / AutoBnB | **Our MVP** |
|---|---|---|---|---|
| Automated narrative | No | Yes | Yes | Yes |
| Multi-agent | N/A | No (single LLM+RAG) | Yes | Yes |
| Explicit MITRE technique correlation per event | No (manual tagging) | Not primary focus | Not primary focus | **Yes — core feature** |
| Evidence-grounded (every claim traceable to a specific parsed log line) | Yes (raw display) but no auto-reasoning | Partial (RAG-retrieved context) | Partial | **Yes — explicit design goal** |
| Scope | Collection/display, or one focused sub-task | Timeline analysis only | Response coordination | Parse → correlate (MITRE) → explain, on real log/artifact data |

**Summary for the report:** existing tools are strong either at *collection/display* (Timesketch, Velociraptor/GRR) or at *single-task LLM automation* (GenDFIR for timelines specifically), and the newest research direction (IRCopilot/AutoBnB) validates multi-agent LLM designs but aims them at response coordination rather than artifact-level evidence correlation. Our project's differentiation is combining a **multi-agent architecture** with **explicit, per-event MITRE ATT&CK correlation** and a hard requirement that every generated claim be **traceable back to a specific parsed log entry** — closing the gap between "the AI wrote a plausible story" and "the AI wrote a story we can verify against the evidence."

## Paper references (for the final report)

1. Loumachi, F. Y. & Ghanem, M. C. (2024–2025). *Advancing Cyber Incident Timeline Analysis Through Rule-Based AI and Large Language Models (GenDFIR)*. arXiv:2409.02572 / MDPI Information, 14(2), 67.
2. Liu, Z. (2025). *AutoBnB: Multi-agent Incident Response with Large Language Models*. 13th International Symposium on Digital Forensics and Security (ISDFS), IEEE.
3. Liu, Z. & Anwar, S. (2025). *AutoBnB-RAG: Extending Multi-agent Incident Response with Retrieval-Augmented Generation*.
4. IRCopilot: *Automated Incident Response with Large Language Models*. arXiv:2505.20945.
5. Google/OSDFIR. *Timesketch* — https://github.com/google/timesketch
6. Rapid Response / Velociraptor project documentation — used as reference for enterprise live-forensics collection design.
