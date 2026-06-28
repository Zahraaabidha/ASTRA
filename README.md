# ASTRA

A two-tier system for automated reverse engineering and risk scoring of fraudulent banking APKs.

## The Problem

Banking trojans on Android caused over 1.24 million attacks in 2024 (Kaspersky, Mobile Malware Evolution 2024). Detection is not the hard part. Modern trojans hide behind encryption and dormancy, and even a flagged sample still needs a scarce human expert to interpret it. Banks receive far more samples than their analysts can review.

## The Solution

ASTRA splits the work across two tiers.

**Tier 1** is a fast XGBoost classifier that triages the routine majority of samples using behavioral composite features rather than raw permission flags.

**Tier 2** is a generative AI analyst reserved for the obfuscated minority. It performs real reverse engineering, the kind of reasoning a human analyst would otherwise do by hand: inferring what encrypted strings decrypt to, resolving indirect method calls, and reconstructing the attack's logical sequence. Every Tier 2 claim is checked against sandbox execution before being reported, so the output is either confirmed (VERIFIED) or clearly marked as unconfirmed (INFERRED).

Findings from both tiers feed a shared knowledge graph that links related samples across a fraud campaign, something no single-sample analysis tool can do.

## Why It Is Different

Existing tools such as VirusTotal Code Insight use language models to summarise a detection after the fact. ASTRA uses the language model to perform the reverse engineering itself, verifies every resulting claim through execution, and links findings across samples to expose entire campaigns rather than single applications. ASTRA does not claim its output is free of hallucination. It claims that every verified finding is backed by execution evidence and every unverified inference is labelled as such.

## Architecture

A format router at ingestion sends APK, PE, macro and script files to the appropriate toolchain. Every format produces the same normalised feature vector, so downstream components work without knowing which format produced the input.

See `docs/architecture_diagram.png` and `docs/ASTRA_Submission.pdf` for the full design.

## Repository Status

This repository is under active development as part of the hackathon's prototype build phase (July to August 2026). See the build roadmap in the submission document for the current stage of each component.

| Component | Status |
|---|---|
| Static extractor and behavioral composites | In progress |
| XGBoost classifier with Platt calibration | In progress |
| Certificate reference database | In progress |
| Tier 2 deobfuscation and citation validation | Planned |
| Knowledge graph | Planned |
| React/TypeScript dashboard | Planned |

## Tech Stack

- **Static analysis**: Apktool, Jadx, Androguard, Apksigner, pefile, LIEF, oletools
- **Dynamic analysis**: Frida, hardened Android emulator, Mitmproxy
- **Machine learning**: XGBoost, LightGBM, SHAP, Platt scaling
- **GenAI**: LLM API, structured prompting, FAISS or Chroma
- **Knowledge graph**: Neo4j or ArangoDB
- **Application**: FastAPI, React, TypeScript, Tailwind CSS
- **Training data**: CICMalDroid2020, EMBER, BODMAS, MalwareBazaar (VirusTotal-verified)
