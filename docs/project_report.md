# ASSETWISE AI — Project Report

## Abstract
Vulnerability prioritisation commonly uses severity, exploitation likelihood and asset context. In practice, asset inventories may contain missing, stale or conflicting fields. This prototype investigates how controlled asset-context degradation can affect remediation rankings. It models data-quality defects, generates plausible scenarios, recalculates vulnerability scores, measures Top-K inclusion probability and rank variation, and presents unstable decisions for human verification. The included implementation uses a synthetic asset inventory and illustrative vulnerability seed records. It demonstrates a reproducible workflow; it does not establish real-world effectiveness.

## 1. Introduction
Organisations may manage large vulnerability queues while relying on asset inventories that are not always complete or current. If a prioritisation model uses asset criticality or exposure, unreliable values can influence remediation order. ASSETWISE focuses on the reliability of the context used to make these decisions.

## 2. Problem statement
How do missing, stale and contradictory asset-context attributes affect vulnerability remediation ranking stability, and can scenario-based uncertainty help identify cases requiring human review?

## 3. Objectives
- Represent asset data quality and provenance.
- Simulate missing, stale and contradictory context.
- Recalculate vulnerability rankings across scenarios.
- Quantify Top-K inclusion and rank variability.
- Present human-review recommendations.
- Compare the proposed analysis with simple ranking baselines.

## 4. Proposed architecture
The prototype contains a vulnerability register, asset inventory, data-quality inspection module, scenario generator, scoring engine, ranking stability engine, review queue and experiment dashboard.

## 5. Methodology
A complete synthetic asset inventory acts as a reference. Controlled perturbations generate degraded copies. In each scenario, asset context is altered according to a fixed random seed and a configured degradation level. Vulnerability scores are recalculated and ranked. The system aggregates ranks across scenarios.

For vulnerability v, empirical Top-K inclusion is:
P_K(v) = count of scenarios where v ranks within K / number of scenarios.

The system also reports median rank, observed minimum and maximum rank, and population standard deviation of ranks. These are descriptive scenario statistics and must not be called calibrated confidence intervals.

## 6. Demonstration scoring
The prototype uses a transparent illustrative score:
30 × normalized CVSS + 25 × EPSS + 20 × KEV + 15 × normalized criticality + 10 × internet exposure.
This formula is created for demonstration and is not an established standard. A research study should justify, tune and validate its scoring method and compare it to appropriate baselines.

## 7. Data
The seeded asset inventory is synthetic. The seeded vulnerability rows are illustrative and require verification against NVD, FIRST EPSS and CISA KEV before publication. Record source snapshots, retrieval dates, versions and provenance in any research dataset.

## 8. Evaluation plan
Recommended comparisons: CVSS-only, EPSS-only, KEV-based, combined rules, context-aware baseline and uncertainty-aware scenario method. Evaluate ranking with Precision@K, Recall@K, NDCG@K, Top-K overlap and rank correlations. Evaluate decision support with review coverage, review precision, risk capture and workload. Use chronological splits if making predictive claims and prevent temporal leakage.

## 9. Limitations
- No live data ingestion.
- Synthetic asset context.
- Illustrative seed vulnerability fields.
- Demonstration score not validated.
- Scenario perturbations do not represent a calibrated model of enterprise inventory errors.
- No real analyst study.
- No real remediation integration.

## 10. Conclusion
ASSETWISE provides a working demonstration of a research workflow for examining ranking stability under asset-context degradation. Further work requires verified public vulnerability snapshots, documented asset-data generation assumptions, stronger baselines, repeated experiments, sensitivity analysis and external validation.
