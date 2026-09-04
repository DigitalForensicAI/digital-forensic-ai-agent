# Literature Review

**Project: Autonomous AI Agent for Digital Forensic Triage and Incident Reconstruction**

Compiled review of 15 related papers, following the requested 12-field template. Bibliographic details were verified against publisher pages, arXiv listings, and citation records; one attribution discrepancy is flagged in Paper 4 below.

---


## Paper 1

- **Title:** DFIR-Metric: A Benchmark Dataset for Evaluating Large Language Models in Digital Forensics and Incident Response

- **Authors:** Bilel Cherif, Tamas Bisztray, Richard A. Dubniczky, Aaesha Aldahmani, Saeed Alshehhi, Norbert Tihanyi

- **Year:** 2025

- **Journal/Conference:** ICONIP 2025 (Neural Information Processing, Springer); preprint arXiv:2505.19973

- **Link/DOI:** https://arxiv.org/abs/2505.19973 ; DOI 10.1007/978-981-95-4367-0_2

### 1. Research Problem
There was no comprehensive, standardized benchmark to evaluate LLMs across both theoretical knowledge and practical hands-on tasks in Digital Forensics and Incident Response (DFIR), despite growing interest in using LLMs for log analysis, memory forensics, and related tasks.

### 2. Existing Methods
Prior work evaluated LLMs on DFIR in narrow, ad hoc ways (e.g., single case studies on report writing or artifact Q&A) without a large-scale, reproducible benchmark spanning knowledge, reasoning, and practical forensic analysis.

### 3. Proposed Methodology
The authors built a three-module benchmark: (1) Knowledge Assessment — 700 expert-reviewed multiple-choice questions drawn from industry certifications and official documentation; (2) Realistic Forensic Challenges — 150 CTF-style tasks requiring multi-step reasoning and evidence correlation; (3) Practical Analysis — 500 disk and memory forensics cases sourced from the NIST Computer Forensics Tool Testing Program (CFTT). Fourteen LLMs were evaluated for both accuracy and cross-trial consistency, and a new Task Understanding Score (TUS) was introduced to differentiate models that fail meaningfully from those that fail near-randomly.

### 4. Dataset/Data Used
700 certification-based MCQs; 150 CTF-style forensic challenges; 500 NIST CFTT disk/memory forensics cases.

### 5. Tools & Technologies
14 different commercial and open-source LLMs; custom evaluation harness released publicly on GitHub (DFIR-Metric).

### 6. Performance/Results
Reports per-model accuracy and consistency across the three modules plus TUS scores; models frequently hallucinate files, commands, paths, or libraries that are not actually present in the forensic image under analysis.

### 7. Key Findings
There is a substantial gap between an LLM's theoretical/certification-style knowledge and its performance on hands-on forensic analysis tasks; hallucination of forensic artifacts is a major, measurable reliability risk.

### 8. Limitations
The benchmark is limited to text-based Q&A, CTF challenges, and CFTT string/data-recovery style cases; it does not capture live, multi-tool, or multi-agent forensic workflows, and evaluation is single-turn rather than iterative/agentic.

### 9. Research Gap
No standardized way existed to compare autonomous or agentic forensic reasoning against ground truth at scale — this motivates the need for agent-level (not just single-model) evaluation frameworks, which is one gap the proposed project's evaluation plan addresses.

### 10. Relevance to Our Project
DFIR-Metric can be used to evaluate the knowledge/reasoning components underlying the proposed system's agents (e.g., the Hypothesis and Correlation Agents), and its Task Understanding Score offers a template metric for judging partially-correct agent outputs rather than a strict right/wrong grade.

### 11. Important Evidence
700 MCQs + 150 CTF tasks + 500 CFTT cases evaluated across 14 LLMs, with hallucination of non-existent forensic artifacts identified as a recurring failure mode.

### 12. Final Summary
DFIR-Metric establishes the first large-scale, reproducible benchmark for evaluating LLM performance on DFIR tasks, showing that current LLMs underperform on hands-on forensic analysis relative to knowledge recall and are prone to hallucination — underscoring both the promise and the present limits of applying LLMs (and, by extension, LLM agents) to forensic investigation, and providing a candidate evaluation instrument for the proposed multi-agent system.


## Paper 2

- **Title:** ForensicLLM: A Local Large Language Model for Digital Forensics

- **Authors:** Binaya Sharma, James Ghawaly, Kyle McCleary, Andrew M. Webb, Ibrahim Baggili

- **Year:** 2025

- **Journal/Conference:** Forensic Science International: Digital Investigation, Vol. 52, Article 301872 (DFRWS EU 2025 selected papers)

- **Link/DOI:** https://doi.org/10.1016/j.fsidi.2025.301872

### 1. Research Problem
General-purpose LLMs lack specialization for digital forensics, and reliance on cloud-based APIs or high-performance hardware restricts their use in resource-limited or privacy-sensitive investigative environments; hallucinations further threaten forensic reliability.

### 2. Existing Methods
Prior approaches used either base general-purpose LLMs or standard Retrieval-Augmented Generation (RAG) pipelines for digital-forensics Q&A, without domain-specific fine-tuning or attention to local/offline deployment.

### 3. Proposed Methodology
The authors fine-tuned a 4-bit quantized LLaMA-3.1-8B model using RAFT (Retrieval-Augmented Fine-Tuning) on question–answer pairs extracted from digital forensic research articles and curated forensic artifacts, then compared it quantitatively (via an automated evaluation such as G-Eval) and qualitatively (via a user survey with DF professionals) against the base model and a standard RAG pipeline.

### 4. Dataset/Data Used
A custom Q&A dataset built from digital forensics research literature and curated forensic artifacts.

### 5. Tools & Technologies
LLaMA-3.1-8B (4-bit quantized), RAFT fine-tuning, a LangChain-style RAG pipeline, G-Eval-based automated evaluation.

### 6. Performance/Results
ForensicLLM outperformed both the base LLaMA-3.1-8B model and the RAG model in correctness and relevance; it accurately attributed sources 86.6% of the time, with 81.2% of responses correctly including both author and title, though the RAG model was preferred for producing more detailed responses.

### 7. Key Findings
A locally deployed, domain-fine-tuned small LLM can match or exceed a general RAG pipeline on forensic knowledge tasks while running entirely offline, preserving case-data privacy; RAG retains an edge in response depth/detail.

### 8. Limitations
The 8B parameter size limits reasoning depth relative to larger frontier models; evaluation focuses on Q&A/knowledge-retrieval and report-writing tasks rather than live, hands-on artifact analysis; the domain scope is bounded by the training corpus.

### 9. Research Gap
There is a lack of locally-deployable, privacy-preserving domain LLMs suitable for embedding inside a multi-agent forensic pipeline without exposing case data to third-party cloud services.

### 10. Relevance to Our Project
Confirms the feasibility of using a fine-tuned local LLM as the reasoning engine for one or more agents in the proposed system (e.g., the Correlation or Hypothesis Agent), supporting a privacy-preserving, on-premises deployment model for sensitive investigative data.

### 11. Important Evidence
86.6% accurate source attribution; 81.2% of responses correctly cited both author and title, versus lower performance for the base model.

### 12. Final Summary
ForensicLLM demonstrates that a locally deployed, RAFT-fine-tuned 8B-parameter LLM can be specialized for digital forensics, outperforming both a base model and a RAG pipeline on correctness and source attribution — directly supporting the proposed project's rationale for running forensic-reasoning agents on private, self-hosted models rather than exposing case evidence to external cloud APIs.


## Paper 3

- **Title:** AutoDFBench: A Framework for AI-Generated Digital Forensic Code and Tool Testing and Evaluation

- **Authors:** Akila Wickramasekara, Alanna Densmore, Frank Breitinger, Hudan Studiawan, Mark Scanlon

- **Year:** 2025

- **Journal/Conference:** DFDS '25 — Digital Forensics Doctoral Symposium (ACM), Brno, Czech Republic

- **Link/DOI:** https://doi.org/10.1145/3712716.3712718

### 1. Research Problem
There was no standardized, reproducible way to validate AI-generated digital forensic code and tools against ground truth — analogous to unit testing in conventional software development — before such code could be trusted in investigations.

### 2. Existing Methods
Investigators reviewed AI-generated forensic scripts manually and ad hoc; NIST's CFTT program provides rigorous testing procedures for traditional forensic tools, but nothing equivalent existed for evaluating LLM/agent-generated code.

### 3. Proposed Methodology
AutoDFBench operates in four phases — data preparation, API handling (querying LLMs with human-engineered prompts), code execution, and result recording/scoring — comparing the generated code's output against NIST CFTT ground truth to compute an 'AutoDFBench Score' per model/task.

### 4. Dataset/Data Used
NIST CFTT forensic string-search test data as the proof-of-concept ground truth (a 2026 follow-up, AutoDFBench 1.0, expands this to file carving, deleted-file recovery, registry recovery, and SQLite recovery across 63 test cases / 10,968 scenarios).

### 5. Tools & Technologies
Five state-of-the-art code-generation LLMs, two programming languages, an open-source benchmarking framework (GitHub: akila-UCD/AutoDFBench).

### 6. Performance/Results
Ran 24,200 unique tests across five LLMs, two expertise-level prompt sets, two languages, and ten iterations per case, producing comparative AutoDFBench Scores and validating output for 121 distinct cases.

### 7. Key Findings
The quality of LLM-generated forensic code varies substantially by model, prompt-expertise level, and programming language; an automated, ground-truth-based scoring pipeline makes iterative benchmarking of GenAI-produced forensic code practically feasible.

### 8. Limitations
The initial version is scoped to string-search tasks only (later expanded in AutoDFBench 1.0); ground truth is bounded by NIST CFTT's existing test suites; the framework evaluates single code-generation outputs, not full multi-agent orchestration.

### 9. Research Gap
There was no reproducible, standardized validator specifically for AI- or agent-generated forensic code and tools prior to real-world deployment — a gap directly relevant to trusting any code or automated scripts an autonomous forensic agent might generate.

### 10. Relevance to Our Project
Provides a ready-made validation methodology that the proposed system's Collector Agent (or any agent generating scripts to parse/process evidence) could be tested against before its outputs are trusted in an investigation, improving the system's overall evidentiary reliability.

### 11. Important Evidence
24,200 unique tests across five LLMs; 121 validated cases spanning two expertise levels, two languages, and ten prompt iterations each.

### 12. Final Summary
AutoDFBench introduces the first standardized, NIST CFTT-grounded benchmarking framework for validating AI-generated forensic code and tools, offering both a precedent and a directly reusable methodology for rigorously testing any code, scripts, or automated tooling produced by the agents in the proposed autonomous forensic-triage system.


## Paper 4

- **Title:** Large Language Models in Digital Forensics: Capabilities, Challenges and Future Directions

- **Authors:** Maxim Chernyshev, Zubair Baig, Naeem Syed, Robin Doss, Malcolm Shore

- **Year:** 2025

- **Journal/Conference:** Forensic Science International: Digital Investigation

- **Link/DOI:** https://www.sciencedirect.com/science/article/pii/S2666281725001830

### 1. Research Problem
The rapid advancement of LLMs has created both opportunities and risks for digital forensic science, but no systematic mapping existed of where in the forensic process LLMs genuinely help versus where they introduce risk.

### 2. Existing Methods
Prior work consisted of scattered individual studies (e.g., ChatGPT-assisted report writing, timeline-analysis experiments, artifact Q&A) that were not unified under a common forensic process framework.

### 3. Proposed Methodology
A systematic literature review of 33 peer-reviewed works, mapped onto the established DFRWS (Digital Forensic Research Workshop) process model, identifying three strategic integration points where LLMs show measurable benefit: pattern recognition during examination, evidence analysis during analysis, and evidence presentation/reporting during presentation.

### 4. Dataset/Data Used
Not applicable (systematic review); the corpus analyzed consists of 33 peer-reviewed papers.

### 5. Tools & Technologies
The DFRWS process model used as the organizing analytical framework.

### 6. Performance/Results
Across the reviewed studies, LLMs achieved 85%–98% accuracy on various forensic subtasks, but this accuracy is inconsistent and can drop sharply on novel or edge-case scenarios (one cited example fell from 91.3% to 74.2% on unfamiliar cases).

### 7. Key Findings
The probabilistic nature of LLM outputs conflicts with the deterministic requirements of forensic science; explainability, reproducibility, and legal admissibility remain largely unresolved; three concrete integration points for LLM assistance are identified across the DFRWS model.

### 8. Limitations
As a review, its conclusions are only as strong as the underlying primary studies, many of which are small-scale or proof-of-concept; no new empirical testing is performed by the authors themselves.

### 9. Research Gap
The survey explicitly identifies significant research gaps in validation frameworks, forensic-ready architectures, and standardized evaluation protocols for LLM-assisted forensics — precisely the gap that a human-verified, multi-agent forensic system (as proposed) aims to help close.

### 10. Relevance to Our Project
Supplies the theoretical/process-model justification for where each proposed agent should sit in the investigative pipeline (Collector → examination; Correlation/Hypothesis → analysis; Report → presentation) and reinforces why the project retains a human analyst for final verification given documented reliability limits of LLM outputs.

### 11. Important Evidence
33-paper systematic review; reported task accuracy in the 85%–98% range with notable degradation (91.3% → 74.2%) on novel/edge-case scenarios.

### 12. Final Summary
This systematic review maps LLM capabilities onto the DFRWS forensic process model, concluding that LLMs offer measurable benefits in pattern recognition, evidence analysis, and reporting, but that probabilistic outputs, explainability, and legal admissibility remain open challenges requiring human oversight — directly motivating the human-in-the-loop verification stage of the proposed agentic system. Note on sourcing: the project brief attributes this title to "Horsman, 2024"; extensive bibliographic search found the paper matching this exact title to be authored by Chernyshev, Baig, Syed, Doss, and Shore (2025) in Forensic Science International: Digital Investigation — this entry reflects the verified authorship, and the discrepancy should be checked against the original source the project intended to cite.


## Paper 5

- **Title:** GenDFIR: Advancing Cyber Incident Timeline Analysis Through Retrieval-Augmented Generation and Large Language Models

- **Authors:** Fatma Yasmine Loumachi, Mohamed Chahine Ghanem, Mohamed Amine Ferrag

- **Year:** 2025 (journal version); first posted 2024

- **Journal/Conference:** Computers, Vol. 14, Issue 2, Article 67 (MDPI); preprint arXiv:2409.02572

- **Link/DOI:** https://arxiv.org/abs/2409.02572

### 1. Research Problem
Manual cyber incident timeline analysis (TA) is slow and labor-intensive, and existing tools struggle to correlate and explain events in a human-understandable narrative rather than raw artifact listings.

### 2. Existing Methods
Prior tools relied on rule-based anomaly detection and manual timeline reconstruction; earlier LLM applications in DFIR focused mainly on report writing rather than automated timeline reasoning.

### 3. Proposed Methodology
GenDFIR is a two-stage pipeline: (1) Rule-Based AI (R-BAI) flags anomalous digital artifacts using predefined rules; (2) the flagged artifacts are converted into embeddings and processed by a zero-shot Llama 3.1 8B model via a Retrieval-Augmented Generation (RAG) agent, which semantically enriches the timeline, predicts potential incident scenarios, and answers investigator queries, including mitigation suggestions.

### 4. Dataset/Data Used
Synthetic cyber incident simulation scenarios generated in a controlled experimental environment.

### 5. Tools & Technologies
Llama 3.1 8B (zero-shot), a custom RAG agent, and a rule-based anomaly-detection (R-BAI) engine.

### 6. Performance/Results
The framework was tested for performance, efficiency, and reliability across synthetic incident scenarios, demonstrating that R-BAI plus RAG plus LLM can automate timeline analysis and surface mitigation strategies as a proof of concept.

### 7. Key Findings
Combining rule-based artifact triage with LLM-based semantic interpretation produces more interpretable and human-readable timeline-analysis outputs than artifact-only tools, though the authors describe this as an initial groundwork rather than a mature system.

### 8. Limitations
Evaluation is confined to synthetic data in a controlled environment rather than real-world incidents; the authors explicitly note the need for further refinement (e.g., fine-tuning) and flag the importance of continuously monitoring R-BAI/LLM outputs to preserve evidence authenticity and integrity.

### 9. Research Gap
There is a lack of production-grade, independently validated timeline-reconstruction agents tested on real-world (rather than synthetic) incident data with rigorous evidence-integrity safeguards.

### 10. Relevance to Our Project
GenDFIR is a near-direct architectural precedent for the proposed system's Timeline Agent: its R-BAI + RAG + LLM design offers a concrete template for chronologically organizing events and semantically enriching them for investigator consumption.

### 11. Important Evidence
Demonstrated RAG-based semantic timeline enrichment and mitigation-strategy generation on synthetic DFIR scenarios, with explicit author acknowledgment that evidence-integrity monitoring is an open requirement.

### 12. Final Summary
GenDFIR shows that pairing rule-based anomaly flagging with a RAG-augmented LLM can automate and semantically enrich cyber incident timeline analysis, serving as a close architectural analogue for the Timeline Agent proposed in this project, while highlighting the unresolved need for real-world validation and rigorous evidence-integrity safeguards that the proposed human-verification stage would help address.


## Paper 6

- **Title:** OCR-APT: Reconstructing APT Stories from Audit Logs using Subgraph Anomaly Detection and LLMs

- **Authors:** Ahmed Aly, Essam Mansour, Amr M. Youssef

- **Year:** 2025

- **Journal/Conference:** Proceedings of the 2025 ACM SIGSAC Conference on Computer and Communications Security (CCS '25), pp. 261–275

- **Link/DOI:** https://arxiv.org/abs/2510.15188 ; https://doi.org/10.1145/3719027.3765219

### 1. Research Problem
Advanced Persistent Threats (APTs) are stealthy and often evade detection in system-level audit logs; existing provenance-graph anomaly detectors suffer from high false-positive rates and produce coarse, non-narrative alerts that fail to explain the full progression of an attack.

### 2. Existing Methods
Prior provenance-graph anomaly detectors relied on brittle node attributes (e.g., file paths, IP addresses), causing spurious correlations and reduced robustness; some LLM-based systems generated explanations but with limited structural grounding and higher hallucination risk.

### 3. Proposed Methodology
OCR-APT combines two components: OCRGCN, a Graph Neural Network (relational GCN plus one-class SVM, trained per node type) that performs subgraph anomaly detection based on behavioral patterns rather than fragile attributes; and an LLM-based 'attack investigator' that uses Retrieval-Augmented Generation to serialize detected anomalous subgraphs and iteratively reconstruct a multi-stage, human-like attack narrative, with each stage validated before the next is generated to reduce hallucination.

### 4. Dataset/Data Used
DARPA Transparent Computing Engagement 3 (TC3), OpTC, and NODLINK provenance/audit-log datasets.

### 5. Tools & Technologies
Relational Graph Convolutional Networks (RGCN), one-class SVM, a Large Language Model with a RAG pipeline.

### 6. Performance/Results
OCR-APT outperforms state-of-the-art systems in both detection accuracy and alert interpretability across all three evaluation datasets, and produces concise, human-readable attack-story reports that reconstruct a majority of the APT kill-chain stages.

### 7. Key Findings
Behavior-based subgraph anomaly detection is substantially more robust than attribute-based detection; a staged, validation-gated approach to LLM narrative generation meaningfully reduces hallucination when reconstructing complex, multi-stage attack stories.

### 8. Limitations
The approach depends on the availability of rich provenance/audit-log data and may not generalize well to environments with sparse logging; the combined GNN-training-plus-iterative-LLM-validation pipeline is computationally intensive; evaluation is limited to public research datasets rather than live enterprise environments.

### 9. Research Gap
Few existing systems combine graph-based behavioral anomaly detection with hallucination-controlled, staged LLM narrative reconstruction — a gap directly relevant to designing a reliable Hypothesis Agent that must propose attack scenarios grounded in evidence rather than speculation.

### 10. Relevance to Our Project
Strongly informs the design of the proposed system's Correlation and Hypothesis Agents, particularly OCR-APT's staged/validated narrative-generation approach for reducing hallucinated attack stories, and its use of kill-chain-stage coverage as an evaluation metric aligns closely with the project's plan to reconstruct initial access, execution, persistence, and exfiltration stages.

### 11. Important Evidence
Evaluated on three established public APT datasets (DARPA TC3, OpTC, NODLINK), outperforming prior state-of-the-art methods on detection accuracy and interpretability.

### 12. Final Summary
OCR-APT combines GNN-based behavioral anomaly detection with a staged, RAG-grounded LLM narrative generator to reconstruct human-readable APT attack stories from audit logs with reduced hallucination, offering a strong and directly applicable architectural precedent for the proposed system's evidence-correlation and attack-hypothesis-generation agents.


## Paper 7

- **Title:** LLM Agents Security Duality: A Comprehensive Survey of Self-Security and Empowered Cybersecurity

- **Authors:** Yiwei Xu, Yong Zhuang, Xuanming Liu, Tian Zhang, Bowen Xiao, Xiaoyang Xu, Delong Jiang, Juan Wang, Hongxin Hu

- **Year:** 2026

- **Journal/Conference:** Artificial Intelligence Review, Vol. 59, Article 174 (Springer); preprint arXiv:2606.28450

- **Link/DOI:** https://doi.org/10.1007/s10462-026-11563-0

### 1. Research Problem
LLM agents' autonomy and tool-use capabilities simultaneously expand the security attack surface (agents as targets) and offer powerful new cyber-defense/offense capabilities (agents as defenders or attackers) — a 'duality' that had not been surveyed holistically.

### 2. Existing Methods
Prior surveys addressed agent trustworthiness, enterprise governance, or core LLM safety in isolation, without linking an agent's own self-security to its use as a cybersecurity tool.

### 3. Proposed Methodology
A systematic survey building a taxonomy of internal and external attack surfaces/threat sources with associated mitigations and evaluation frameworks (self-security), alongside an agent-empowerment framework mapped to the full cyber offense-defense lifecycle (empowered cybersecurity), including a review of multi-agent incident-response systems such as IPCopilot (a 4-agent inference-action-reflection loop) and AutoBnB/AutoBnB-RAG (RAG-augmented incident-response game agents).

### 4. Dataset/Data Used
Not applicable (survey); synthesizes benchmarks and frameworks reported across the surveyed literature.

### 5. Tools & Technologies
Not applicable — a conceptual taxonomy rather than an implemented system.

### 6. Performance/Results
Identifies a self-reinforcing 'positive feedback synergy' between agent self-security and agent-empowered cybersecurity, and catalogs benchmarks/testbeds spanning both domains.

### 7. Key Findings
Multi-agent, role-simulating incident-response systems (e.g., a 4-agent inference-action-reflection loop that decomposes large investigative targets into traceable subtasks) are an emerging, effective pattern for suppressing long-context loss and logical breaks in complex security investigations.

### 8. Limitations
As a survey it does not produce new empirical results; the fast pace of agentic-AI security research means parts of the taxonomy may already be dated; several cited systems (e.g., IPCopilot, AutoBnB) are themselves early-stage and not independently validated by this survey.

### 9. Research Gap
There is limited standardized guardrail/evaluation coverage for multi-agent forensic or incident-response systems specifically (as distinct from general-purpose agent safety) — directly relevant to securing the proposed system itself, not just to using it as an investigative tool.

### 10. Relevance to Our Project
Highlights both an opportunity (validated multi-agent incident-response architectures to emulate, e.g., IPCopilot's task-decomposition loop) and a risk (the proposed forensic-agent system is itself an LLM-agent system and must consider its own attack surface and self-security, not only its investigative capability).

### 11. Important Evidence
Documents specific multi-agent incident-response precedents (IPCopilot's 4-agent loop; AutoBnB/AutoBnB-RAG) as validated architectural patterns for decomposing complex security tasks.

### 12. Final Summary
This survey frames LLM agents' cybersecurity role as a two-way duality — agents as both a security liability and a security asset — and documents emerging multi-agent incident-response architectures, reinforcing that the proposed forensic-agent system should be designed with its own self-security and human-verification safeguards in mind, not solely its investigative capability.


## Paper 8

- **Title:** LLM-APTDS: A High-Precision Advanced Persistent Threat Detection System for Imbalanced Data Based on Large Language Models with Strong Interpretability

- **Authors:** Longjing Yang, Ayong Ye, Yuanhuang Liu, Wenting Lu, Chuang Huang

- **Year:** 2025

- **Journal/Conference:** Future Generation Computer Systems

- **Link/DOI:** https://doi.org/10.1016/j.future.2025.108315

### 1. Research Problem
APT detection on class-imbalanced data commonly suffers from poor precision and low interpretability in existing detection systems, limiting analyst trust and actionability.

### 2. Existing Methods
Traditional machine-learning and graph-based APT detectors that struggle with severe class imbalance and provide limited explanation for why a given event was flagged as malicious.

### 3. Proposed Methodology
LLM-APTDS uses a multi-model collaborative detection architecture in which LLM semantic understanding precisely localizes log anomalies; a K-nearest-neighbor graph reconstruction algorithm rebuilds the relevant neighborhood graph around malicious entities to add contextual awareness; and a cyclically enhanced analysis mechanism guided by the MITRE ATT&CK knowledge graph lets the LLM iteratively reason and generate multi-dimensional threat-intelligence reports with layered explanations and automated mitigation strategies.

### 4. Dataset/Data Used
DARPA Transparent Computing Engagement 3 (TC-E3) dataset.

### 5. Tools & Technologies
Large Language Models, K-nearest-neighbor graph reconstruction, the MITRE ATT&CK knowledge graph.

### 6. Performance/Results
Compared to baseline methods, the system achieves a 5% improvement in detection precision and a 4% increase in F1-score, alongside higher-quality, multi-dimensional threat-intelligence reports.

### 7. Key Findings
Coupling LLM-based semantic reasoning with MITRE ATT&CK-guided iterative analysis improves both detection precision on imbalanced data and the interpretability/actionability of generated reports.

### 8. Limitations
Evaluation is limited to a single dataset (DARPA TC-E3); the focus on class-imbalance handling may not generalize equally well to all attack types; the computational overhead of iterative, cyclically enhanced LLM reasoning is not fully characterized.

### 9. Research Gap
Relatively few APT detection systems combine explicit class-imbalance handling with ATT&CK-grounded, explainable LLM reporting — a gap directly relevant to the proposed project's plan to correlate evidence against MITRE ATT&CK.

### 10. Relevance to Our Project
Directly supports the design of the proposed Correlation Agent, which is explicitly intended to compare collected evidence against known attack techniques and IOCs using MITRE ATT&CK; this paper's ATT&CK-guided cyclic reasoning mechanism is a concrete candidate technique for that agent.

### 11. Important Evidence
+5% precision and +4% F1-score improvement over baseline methods on the DARPA TC-E3 dataset.

### 12. Final Summary
LLM-APTDS demonstrates that pairing LLM-based log-anomaly localization with MITRE ATT&CK-guided iterative reasoning improves APT detection precision on imbalanced data while producing interpretable, mitigation-oriented threat reports — directly validating the proposed system's plan to use MITRE ATT&CK as the backbone of its Correlation Agent.


## Paper 9

- **Title:** CyberLLM-FINDS: Instruction-Tuned Fine-tuning of Domain-Specific LLMs with Retrieval-Augmented Generation and Graph Integration for MITRE Evaluation

- **Authors:** Vasanth Iyer, Leonardo Bobadilla, S. S. Iyengar (arXiv preprint); a related conference poster version credits Vamshikrishna Challa et al.

- **Year:** 2026

- **Journal/Conference:** arXiv preprint 2601.06779 (poster presented at the 2026 Trusted CI Regional Cybersecurity Summit)

- **Link/DOI:** https://arxiv.org/abs/2601.06779

### 1. Research Problem
General-purpose LLMs lack cybersecurity domain expertise needed for MITRE ATT&CK-grounded threat-intelligence reasoning, and this problem is compounded under limited hardware and short-context-window constraints.

### 2. Existing Methods
Plain instruction-tuned small LLMs (e.g., base Gemma-2B) without retrieval or graph grounding, and standard 'flat' RAG pipelines that lack structured tactic/technique relationships.

### 3. Proposed Methodology
The authors LoRA-fine-tuned a 2B-parameter LLM (Gemma-2B) on a curated MITRE ATT&CK-aligned instruction dataset (2,398 prompt–response pairs), then layered a RAG pipeline plus a graph-based reasoning module (using STIX-formatted threat-intelligence data) that encodes entity-neighborhood context and ATT&CK tactic chains; they compared Pure RAG, Graph+LLM, and GraphRAG+GNN pipelines using an automated LLM-judge scoring system across five dimensions (relevance, completeness, accuracy, specificity, clarity).

### 4. Dataset/Data Used
A custom 2,398-pair MITRE ATT&CK instruction dataset and a STIX-based threat-intelligence graph.

### 5. Tools & Technologies
Gemma-2B, LoRA fine-tuning, a RAG pipeline, GNN-based graph retrieval, an automated LLM-judge evaluator, a single 24GB GPU for training.

### 6. Performance/Results
GraphRAG+GNN achieved the highest overall LLM-judge score (8.00/10), with the strongest gains in accuracy and specificity; Pure RAG led in clarity and speed, winning 3 of 5 head-to-head category comparisons (average score 7.87 vs. Graph+LLM's 7.16).

### 7. Key Findings
Structured graph context combined with lightweight GNN-based scoring measurably improves interpretability and retrieval quality for MITRE ATT&CK-style queries beyond fine-tuning or RAG alone; small-model deployment required careful tuning (token length of 397, batch size of 4) to fit 24GB GPU memory constraints.

### 8. Limitations
The small 2B-parameter base model limits reasoning depth relative to larger models; the training dataset (2,398 pairs) is modest in scale; evaluation relies on an automated LLM-judge rather than expert human forensic/security analysts.

### 9. Research Gap
There is limited work on resource-efficient, locally fine-tunable, ATT&CK-graph-grounded LLMs suitable for constrained hardware — directly relevant to deploying lightweight, on-premises correlation-agent models rather than relying on large cloud-hosted LLMs.

### 10. Relevance to Our Project
Offers a resource-efficient alternative architecture (LoRA fine-tuning plus GraphRAG over ATT&CK/STIX data) for the proposed Correlation Agent, potentially allowing it to run on modest local hardware while remaining ATT&CK-aware, complementing the larger-model approaches seen in ForensicLLM and LLM-APTDS.

### 11. Important Evidence
GraphRAG+GNN average LLM-judge score of 8.00 versus 7.87 (Pure RAG) and 7.16 (Graph+LLM) across five evaluation dimensions on MITRE ATT&CK queries.

### 12. Final Summary
CyberLLM-FINDS shows that a small, LoRA-fine-tuned LLM augmented with graph-based (GraphRAG+GNN) retrieval over MITRE ATT&CK/STIX data can outperform plain RAG or graph-only approaches on ATT&CK-style reasoning, offering a lightweight, resource-efficient pattern the proposed Correlation Agent could adopt for technique-mapping under constrained hardware.


## Paper 10

- **Title:** CyberSleuth: Autonomous Blue-Team LLM Agent for Web Attack Forensics

- **Authors:** Stefano Fumero, Kai Huang, Matteo Boffa, Danilo Giordano, Marco Mellia, Zied Ben Houidi, Dario Rossi

- **Year:** 2025

- **Journal/Conference:** arXiv preprint 2508.20643 (Politecnico di Torino / Huawei Technologies France)

- **Link/DOI:** https://arxiv.org/abs/2508.20643

### 1. Research Problem
Defensive (blue-team) forensic investigation of web application attacks has received comparatively little attention from LLM-agent research, which has focused mainly on offensive (red-team) applications, leaving manual post-attack forensic analysis slow and under-automated.

### 2. Existing Methods
Earlier LLM-agent cybersecurity work concentrated on red-team tasks such as vulnerability discovery and penetration testing; there was little systematic study of agent-design choices specifically for defensive, forensic investigation.

### 3. Proposed Methodology
The authors systematically benchmark four agent architectures across six LLM backends. The modular design uses specialized sub-agents (e.g., a decoupled Flow Summariser) that process packet-level traces and application logs to identify the targeted service, the exact exploited CVE, and whether the attack succeeded, ultimately generating structured, human-readable forensic reports.

### 4. Dataset/Data Used
20 controlled web-attack scenarios of increasing complexity (targeting Apache, Nginx, VPN gateways, and CMS applications), plus 10 held-out incident traces from 2025 to test generalization, and a human study with 22 security experts rating report quality.

### 5. Tools & Technologies
Multiple LLM backends including GPT-5, o3, and DeepSeek R1; the open-sourced CyberSleuth platform and benchmark suite.

### 6. Performance/Results
The best-performing architecture achieves approximately 90% service-identification accuracy and 80% exact-CVE detection accuracy on the independent 2025 held-out test set; expert reviewers rated CyberSleuth's reports as complete, useful, and coherent, with a slight preference for DeepSeek R1-generated reports.

### 7. Key Findings
Decoupling evidence summarization from reasoning (via a dedicated Flow Summariser sub-agent) improves accuracy and reduces cost (averaging about 5 reasoning steps); noisy or uninformative logs can distract the agent and sometimes reduce accuracy, particularly for GPT-5.

### 8. Limitations
Scope is limited to web-application attacks rather than full-system or host-level forensics; the approach depends on availability of clean packet/log traces; only 30 total incident scenarios were evaluated overall.

### 9. Research Gap
Few autonomous agents are purpose-built and rigorously benchmarked specifically for blue-team forensic reconstruction (as opposed to detection alone) — this is precisely the niche of the proposed multi-agent system, though CyberSleuth's scope is limited to web attacks rather than broader digital forensics (disk, memory, network-wide incidents).

### 10. Relevance to Our Project
Provides a directly reusable multi-agent, multi-backend benchmarking methodology (architecture × LLM-backend grid combined with human expert evaluation) that the proposed system can adapt to evaluate its own Collector, Timeline, Correlation, Hypothesis, and Report Agents.

### 11. Important Evidence
~90% service-identification accuracy and 80% exact-CVE detection accuracy on an independent 2025 test set; validated via a 22-expert human evaluation study.

### 12. Final Summary
CyberSleuth is an autonomous, modular LLM-agent system for blue-team web-attack forensics that identifies compromised services, exact CVEs, and attack outcomes with high accuracy; its rigorous architecture/backend benchmarking methodology and human-expert evaluation protocol closely parallel — and can directly inform the evaluation plan for — the proposed autonomous forensic-triage agent system.


## Paper 11

- **Title:** An End-to-End Framework for Functionality-Embedded Provenance Graph Construction and Threat Interpretation (Auto-Prov)

- **Authors:** Kushankur Ghosh, Mehar Klair, Kian Kyars, Euijin Choo, Jörg Sander

- **Year:** 2026

- **Journal/Conference:** arXiv preprint 2603.17100 (University of Alberta)

- **Link/DOI:** https://arxiv.org/abs/2603.17100

### 1. Research Problem
Building provenance graphs from raw system logs currently depends on brittle, manually engineered rules; existing graphs also lack functional/semantic context for system entities and provide limited support for analyst investigation.

### 2. Existing Methods
Prior provenance-graph-based anomaly detectors used manually crafted regular-expression rules to extract entities, types, names, and interactions from logs, which assumes prior knowledge of all log formats and does not scale to heterogeneous, evolving systems.

### 3. Proposed Methodology
Auto-Prov uses LLMs to automatically construct provenance graphs from heterogeneous, evolving logs by clustering previously unseen log types and efficiently generating extraction rules; it embeds system-level functional attributes into graph entities via a combination of LLM inference and behavior-based estimation for both known and unseen entities; the enriched graphs feed existing provenance-graph anomaly detectors, and detected attacks are summarized into natural-language text to assist analyst investigation.

### 4. Dataset/Data Used
Diverse, heterogeneous system logs evaluated across four state-of-the-art provenance-graph-based anomaly detectors.

### 5. Tools & Technologies
Large Language Models (for log-type clustering, rule generation, and functional-context inference) integrated with existing provenance-graph anomaly detection systems.

### 6. Performance/Results
Functionality-embedded, LLM-constructed graphs improved performance and interpretability across all four provenance-graph detectors tested, compared to detectors run on graphs built with conventional manual rules.

### 7. Key Findings
Automating provenance-graph construction and embedding functional context substantially reduces manual rule-engineering effort while producing more analyst-usable, natural-language attack summaries than raw graph outputs alone.

### 8. Limitations
The framework depends on the quality of LLM inference for unseen entity types, introducing a risk of misclassification; it adds computational overhead to the overall detection pipeline; evaluation is conducted on offline/log-based datasets rather than live production systems.

### 9. Research Gap
Much prior LLM-graph-summarization work assumes the LLM itself acts as the threat detector; Auto-Prov instead cleanly separates graph construction/enrichment from detection — a modular separation of concerns directly relevant to designing a multi-agent pipeline with distinct evidence-collection and reasoning stages.

### 10. Relevance to Our Project
Provides a concrete technique the proposed Collector Agent could adopt to automatically build and normalize provenance-style evidence graphs from heterogeneous log sources (rather than requiring hand-written parsers for every source), directly feeding structured evidence to the Timeline and Correlation Agents downstream.

### 11. Important Evidence
Evaluated across four state-of-the-art provenance-based anomaly detectors, with consistent performance and interpretability improvements attributed to functionality-embedded graphs.

### 12. Final Summary
Auto-Prov automates provenance-graph construction from heterogeneous, evolving logs using LLMs, embeds functional context into graph entities, and translates detected anomalies into natural-language summaries — offering a directly applicable technique for the proposed system's Collector Agent to normalize diverse forensic artifact sources into a structured, analyzable evidence graph.


## Paper 12

- **Title:** A Framework for Integrated Digital Forensic Investigation Employing AutoGen AI Agents

- **Authors:** Akila Wickramasekara, Mark Scanlon

- **Year:** 2024

- **Journal/Conference:** 12th International Symposium on Digital Forensics and Security (ISDFS 2024), IEEE

- **Link/DOI:** https://doi.org/10.1109/ISDFS60797.2024.10527235

### 1. Research Problem
Digital investigations increasingly involve large, complex, heterogeneous volumes of data, and investigators need tooling that bridges knowledge gaps and automates repetitive analysis tasks across the investigative workflow.

### 2. Existing Methods
Traditional single-tool, largely manual digital-forensic workflows, and standalone LLM chat interfaces (e.g., ChatGPT used ad hoc) applied without task orchestration, memory, or tool integration across the investigation.

### 3. Proposed Methodology
The authors propose an integrated digital forensic investigation framework built on Microsoft's AutoGen multi-agent orchestration library, coordinating multiple pretrained LLMs as collaborating AI agents that generate forensic scripts, automate repetitive tasks, and assist in interpreting complex evidence — explicitly aiming to bridge knowledge gaps among investigators and enhance overall efficiency.

### 4. Dataset/Data Used
Presented primarily as a framework/architecture contribution with illustrative use cases rather than a large-scale empirical benchmark.

### 5. Tools & Technologies
Microsoft AutoGen, multiple pretrained LLMs functioning as collaborating agents.

### 6. Performance/Results
Demonstrates the feasibility of multi-agent LLM orchestration for digital forensic tasks at the framework/architecture level, rather than reporting large-scale quantitative accuracy metrics.

### 7. Key Findings
Multi-agent LLM orchestration (via AutoGen) is a workable architecture for coordinating distinct digital-forensic sub-tasks across multiple specialized AI agents, improving the efficiency and productivity of investigations relative to single-model or single-tool approaches.

### 8. Limitations
As an early-stage conceptual framework paper (2024), it offers limited large-scale empirical validation compared to later, more rigorous benchmarks (e.g., AutoDFBench, produced by an overlapping author group specifically to address this validation gap).

### 9. Research Gap
The paper lacked a standardized way to validate the AI-generated outputs of such multi-agent frameworks against ground truth — a gap the same research group later addressed with AutoDFBench (2025/2026).

### 10. Relevance to Our Project
This is arguably the closest direct architectural precedent to the proposed project overall — a multi-agent, AutoGen-style team of LLM agents automating digital forensic investigation — and is a foundational reference the project should explicitly build on and differentiate from (e.g., by adding MITRE ATT&CK-based correlation, a dedicated Hypothesis Agent for attack-scenario reconstruction, and rigorous ground-truth evaluation via DFIR datasets or CTF challenges).

### 11. Important Evidence
Establishes AutoGen-based multi-agent LLM orchestration as a validated architectural direction for digital forensics, later extended empirically by the same authors' AutoDFBench benchmarking work.

### 12. Final Summary
This foundational 2024 paper proposes using Microsoft AutoGen to orchestrate multiple pretrained LLMs as collaborating agents across the digital forensic investigation workflow, directly prefiguring the multi-agent architecture proposed in this project, while leaving open the empirical-validation gap that subsequent benchmarks (e.g., AutoDFBench) and the current project both aim to address.


## Paper 13

- **Title:** A Privacy-Preserving Multi-Agent LLM Framework for Automated Incident Response and Digital Forensics on Personal Devices

- **Authors:** Swathi Priya Choppala, Korada Chaitanya, Kommu Tejasri, Kona Venkata Lakshmi, Kota Harika Seshamani

- **Year:** 2026

- **Journal/Conference:** International Journal of Engineering Research & Technology (IJERT), Vol. 15, Issue 4

- **Link/DOI:** https://doi.org/10.5281/zenodo.19681278

### 1. Research Problem
Personal computing devices increasingly need automated incident response and digital forensics capability, but sending sensitive personal data to cloud-hosted LLMs for this purpose raises serious privacy concerns.

### 2. Existing Methods
Cloud-based LLM incident-response assistants and single-agent forensic tools that typically require uploading potentially sensitive personal data to third-party services for analysis.

### 3. Proposed Methodology
The paper proposes a multi-agent LLM system incorporating Retrieval-Augmented Generation (RAG) and multiple safety layers, explicitly designed to provide automated incident response and digital forensics for personal devices while minimizing exposure of sensitive user data, addressing the research question of how such a system can provide reliable forensic/IR support without compromising privacy.

### 4. Dataset/Data Used
Not fully detailed in publicly available material; the paper is framed as an applied/systems contribution targeting personal-device incident scenarios rather than a large public benchmark dataset.

### 5. Tools & Technologies
A multi-agent LLM architecture, a RAG component, and multiple safety-layer mechanisms.

### 6. Performance/Results
The paper presents and evaluates a working privacy-preserving multi-agent pipeline for personal-device incident response and forensics; detailed quantitative results were not available from the retrieved abstract and would require accessing the full text.

### 7. Key Findings
Privacy preservation and multi-agent collaboration are treated as first-class design constraints — rather than afterthoughts — for consumer-facing forensic/incident-response tooling.

### 8. Limitations
Available material is limited in technical depth relative to venues like DFRWS or CCS; the scope is confined to personal devices rather than enterprise or network-level forensics; full quantitative evaluation details were not accessible from the search results used to compile this review.

### 9. Research Gap
Most multi-agent DFIR research reviewed here (e.g., OCR-APT, CyberSleuth) targets enterprise or server-side telemetry; comparatively little published work addresses privacy-preserving multi-agent forensics specifically for personal or consumer devices.

### 10. Relevance to Our Project
Reinforces that the proposed system should explicitly build in data-privacy and confidentiality safeguards (echoing ForensicLLM's local-deployment rationale) when its agents process potentially sensitive personal or organizational evidence, and offers a precedent for a 'safety layer' design pattern alongside the human-verification stage already planned.

### 11. Important Evidence
Proposes and evaluates a multi-agent + RAG + multi-safety-layer architecture explicitly targeting personal-device privacy preservation in incident response and forensics.

### 12. Final Summary
This paper proposes a privacy-preserving multi-agent LLM framework — combining RAG with multiple safety layers — for automated incident response and digital forensics on personal devices, underscoring the importance of privacy-by-design in multi-agent forensic architectures such as the one proposed in this project.


## Paper 14

- **Title:** AIR: Improving Agent Safety through Incident Response

- **Authors:** Zibo Xiao, Jun Sun, Junjie Chen

- **Year:** 2026

- **Journal/Conference:** arXiv preprint 2602.11749; accepted as an ICML 2026 poster

- **Link/DOI:** https://arxiv.org/abs/2602.11749

### 1. Research Problem
Existing LLM-agent safety mechanisms focus almost exclusively on preventing failures proactively, leaving agents with very limited capability to detect, contain, or recover from safety incidents once they actually occur during execution.

### 2. Existing Methods
Model-centric approaches (RLHF, safety-oriented fine-tuning) and runtime-enforcement/guardrail approaches that attempt to block unsafe actions in advance, but provide no structured mechanism for handling incidents after they happen.

### 3. Proposed Methodology
AIR (Agent Incident Response) introduces a novel Domain-Specific Language (DSL) integrated directly into an agent's execution loop, enabling the agent to autonomously detect incidents, contain their impact, recover the environment to a safe state, and eradicate the root cause by synthesizing new guardrail rules to prevent recurrence; the framework is evaluated across three representative agent types — code agents, embodied agents, and computer-use agents.

### 4. Dataset/Data Used
Task and risk-category datasets spanning code, embodied, and computer-use agent domains; manually authored AIR rules, plus experiments evaluating automatic, LLM-driven rule generation.

### 5. Tools & Technologies
A custom Domain-Specific Language (DSL), LLM-based code/embodied/computer-use agents, and an automated guardrail-rule synthesis pipeline.

### 6. Performance/Results
AIR effectively detects incidents and executes appropriate containment and recovery actions across all three agent types studied, and the authors show it is feasible to automatically synthesize eradication guardrail rules from detected incidents using an LLM.

### 7. Key Findings
The authors conclude that incident response is 'both feasible and essential as a first-class mechanism for improving agent safety,' complementing — rather than replacing — proactive, prevention-focused safety measures.

### 8. Limitations
Evaluation covers three specific agent domains (code, embodied, computer-use) but not forensic or security-investigation agents specifically; the quality of DSL-based rules depends heavily on the authoring process, whether manual or automatically generated.

### 9. Research Gap
No prior general-purpose framework treated post-hoc incident response as a first-class agent-safety mechanism; more specifically, no existing work applies this 'incident response for agents' concept reflexively to a forensic-investigation agent system itself.

### 10. Relevance to Our Project
Directly applicable to the proposed forensic-agent system's own operational safety: because the proposed system is itself a multi-agent pipeline, AIR's detect-contain-recover-eradicate lifecycle could safeguard the forensic agents' own operation (e.g., if the Collector Agent mishandles or corrupts evidence), complementing the human-verification stage already planned in the project.

### 11. Important Evidence
Empirical detection, containment, and recovery results reported across three distinct agent domains, plus dedicated experiments on automated guardrail-rule synthesis (Section 4.4 of the paper).

### 12. Final Summary
AIR introduces a domain-specific-language-based incident-response lifecycle (detect, contain, recover, eradicate) for LLM agents themselves, demonstrating that post-hoc incident response is a necessary complement to proactive agent-safety measures — a concept the proposed forensic-agent system could adopt reflexively to protect its own multi-agent operation, in addition to investigating cyberattacks on external systems.


## Paper 15

- **Title:** A Survey on Agentic Security: Applications, Threats and Defenses

- **Authors:** Asif Shahriar, Md Nafiu Rahman, Sadif Ahmed, Farig Sadeque, Md Rizwan Parvez

- **Year:** 2025 (v1 October 2025; revised December 2025 and June 2026)

- **Journal/Conference:** arXiv preprint 2510.06445 (BRAC University and Qatar Computing Research Institute)

- **Link/DOI:** https://arxiv.org/abs/2510.06445

### 1. Research Problem
The shift from passive LLMs to autonomous LLM agents in cybersecurity has produced over 160 scattered papers (2024–2025) without a unifying framework connecting agent capabilities, vulnerabilities, and defenses.

### 2. Existing Methods
Prior surveys addressed only fragments of the landscape — technical vulnerabilities, trustworthiness, enterprise governance, or core LLM safety — separately, without a holistic 'applications–threats–defenses' structure.

### 3. Proposed Methodology
The authors present the first holistic survey of agentic security, structured around three pillars — Applications (spanning offensive red-team agents and defensive detection/forensics/remediation agents), Threats, and Defenses — synthesizing more than 160 papers into a unified taxonomy alongside a catalog of benchmarks and testbeds.

### 4. Dataset/Data Used
Not applicable (survey); the corpus analyzed comprises over 160 papers published primarily in 2024–2025.

### 5. Tools & Technologies
Not applicable — a taxonomic/organizational framework rather than an implemented system.

### 6. Performance/Results
Produces a structured taxonomy (Applications / Threats / Defenses / Benchmarks) with a comparison table against prior, narrower surveys, explicitly documenting red-team offensive agents alongside defensive and forensic agent applications.

### 7. Key Findings
The survey identifies systemic issues in the field, including heavy reliance on a small set of LLM backends (a 'GPT monopoly'), uneven coverage of threats and modalities, and significant benchmark fragmentation across agentic-security research.

### 8. Limitations
As a survey it does not generate new empirical results; the taxonomy reflects a very fast-moving field that may shift quickly; the breadth of coverage (160+ papers) can come at some cost to depth on any single subdomain, such as forensic incident reconstruction specifically.

### 9. Research Gap
The survey explicitly highlights forensic and incident-response agents as an application category still comparatively underexplored relative to offensive red-teaming agents, and calls out fragmented benchmarking as a field-wide problem — directly matching the motivation for the proposed project.

### 10. Relevance to Our Project
Provides the broadest contextual map of where the proposed autonomous forensic-triage agent sits within the wider 'agentic security' landscape (as a defensive/forensics application), and flags benchmark fragmentation as a challenge the project's evaluation plan (using public DFIR datasets or CTF forensic challenges) should explicitly try to address rather than reproduce.

### 11. Important Evidence
Synthesizes 160+ papers from 2024–2025 into the first unified Applications/Threats/Defenses taxonomy for agentic security, including a direct comparison table against five prior narrower surveys.

### 12. Final Summary
This is the first holistic survey of agentic security, organizing 160+ papers into applications (including forensic/defensive agents), threats, and defenses, and explicitly identifying benchmark fragmentation and uneven coverage of defensive/forensic use cases — reinforcing both the timeliness and the current under-coverage of autonomous forensic-agent research that this project directly addresses.
