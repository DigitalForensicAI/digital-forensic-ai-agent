# Autonomous AI Agent for Digital Forensic Triage and Incident Reconstruction

An AI system that automates digital forensic triage. It ingests forensic logs, normalizes them into a canonical event format, reconstructs the incident timeline, correlates activity against the MITRE ATT&CK framework, builds a provenance graph of the attack, and uses a locally hosted large language model to reconstruct the incident along the attack kill chain, grounding every generated claim in real evidence and verifying it automatically.

The system's distinguishing feature is a deterministic verification layer that runs outside the language model and grounds every claim to a real artifact identifier, so the system cannot fabricate evidence without detection.

## Overview

Manual digital forensic investigation is slow and error prone across large volumes of disk, memory, and network artifacts. Rule based tools match only fixed patterns, while general language models can hallucinate evidence that does not exist. This project combines deterministic tooling with grounded language model reasoning: tools perform parsing, normalization, correlation, and graph construction, and the language model reasons only over evidence that already exists, with every claim checked against the source artifacts.

## Pipeline

```
Forensic log input
      |
Collector and canonical events        (deterministic)
      |
Timeline reconstruction               (deterministic)
      |
MITRE ATT&CK correlation and IOC      (deterministic)
      |
Provenance graph                      (deterministic)
      |
Hypothesis agent, kill-chain reasoning  (local LLM)
      |
Verification and grounding score      (deterministic)
      |
Adversarial validation                (evaluation)
      |
Investigation report
```

## Components

### Collector and Canonical Events
Ingests raw log data and normalizes each record into the canonical event schema, assigning every event a unique artifact identifier. Normalized events are held in a SQLite event store shared across the pipeline. The canonical schema and artifact identifier convention established here are the foundation the entire grounding mechanism depends on.

### Timeline
Orders events chronologically and groups related activity into sessions, producing a unified incident timeline.

### Correlation
Matches each event against a curated set of MITRE ATT&CK techniques and an indicator of compromise list, tagging suspicious events with their technique identifiers and indicator status. The output preserves every event and adds the correlation fields consumed downstream.

### Provenance Graph
Transforms the tagged events into a directed relationship graph of users, processes, files, network endpoints, and commands. Every edge is annotated with the artifact identifier of its source event, so no relationship exists in the graph without a corresponding observation.

### Hypothesis Agent
Reconstructs the incident along the ATT&CK kill chain, initial access, execution, persistence, discovery, and exfiltration, using a locally hosted language model. Each stage is produced as a structured hypothesis constrained to cite the artifact identifiers that support it. Stages without supporting evidence are marked explicitly rather than inferred, so the reconstruction reflects only what the evidence supports.

### Verification and Grounding Score
Validates the language model output against the evidence using a deterministic, lexical and field based relevance verifier that runs independently of the model. Each claim is checked on two levels: whether every cited artifact identifier exists in the evidence, and whether the cited event is lexically relevant to the claim. Claims are classified as grounded, weakly supported, or unsupported, and a grounding score reports the proportion of fully grounded claims. The relevance threshold is tuned empirically.

### Adversarial Validation
Evaluates robustness under adversarial input. Crafted evidence cases are processed through two paths, an unguarded model call without grounding or verification, and the full grounded pipeline, and the results are compared. In testing, the unguarded path fabricated multiple unsupported attack stages from minimal evidence, while the grounded pipeline asserted only evidence backed claims and its verifier flagged the unsupported ones. This work is defensive robustness testing and references established concepts in prompt injection and jailbreak robustness, the OWASP LLM Top 10, and MITRE ATLAS.

### Report Generation
Compiles the verified reconstruction into a structured investigation report containing an executive summary, timeline, detected techniques, the evidence grounded narrative, the grounding score, and an evidence appendix, with export to document formats.

## Dataset
A research grounded incident dataset models a documented APT29 style attacker technique sequence and is accompanied by a documented ground truth narrative with MITRE technique labels, providing a reference against which the system's output is evaluated.

## Design Principle

Deterministic tooling performs all parsing, normalization, correlation, graph construction, and verification. The language model is confined to reasoning over already structured evidence and may not perform extraction or introduce facts. Every claim in the final report is traceable to one or more source artifact identifiers.

## Technology

Python, SQLite, NetworkX, and a locally hosted language model served through Ollama. The model provider is abstracted, allowing a hosted model to be substituted without changes to the reasoning or verification logic, and supporting a fully offline deployment appropriate for privacy sensitive evidence.

## Running the Pipeline

Prerequisites: Python 3.10 or later, and Ollama with the configured local model available.

```
python main.py --input data/samples/correlations.json
```

The command runs the full pipeline and writes the investigation report and provenance graph to the output directory. Individual stages, including the hypothesis agent, the verifier, and the adversarial validation, can also be run independently.

## Team

The project is developed by a team of five, with each member owning a stage of the pipeline.

| Member | Register Number | Responsibility |
|---|---|---|
| Shahal Abdulla K M | 23BCY10087 | Collector, canonical events, and timeline |
| Mohamad Nahal S | 23BCY10125 | Threat correlation, MITRE ATT&CK, and IOC detection |
| Shikha S | 23BCY10298 | Provenance graph, kill-chain reasoning, and verification |
| Devkrishna U S | 23BCY10123 | AI and LLM security, evaluation, and metrics |
| Riya Singh | 23BCY10289 | Dataset engineering and forensic research |

## Project Status

The system implements a complete end to end pipeline from log input to a verified, evidence grounded investigation report, including kill chain hypothesis reasoning, lexical relevance verification, and adversarial robustness validation, evaluated against a documented ground truth.

Planned extensions include retrieval augmented correlation, embedding based semantic verification, competing hypothesis generation, multi agent orchestration, human in the loop review, and evaluation across additional public datasets.