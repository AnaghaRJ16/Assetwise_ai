# Research methodology and next steps

## Research questions
RQ1. How do missing, stale and contradictory asset-context attributes affect vulnerability remediation ranking stability?
RQ2. Which fields and defect mechanisms produce the greatest ranking variation?
RQ3. Can scenario-based analysis identify unstable Top-K decisions and guide human review under a defined review budget?

## Hypotheses
H1. Increasing asset-context degradation increases ranking instability relative to complete reference records.
H2. The effect differs across missing, stale and contradictory data mechanisms.
H3. A data-quality-aware review policy can identify unstable decisions while maintaining high-priority vulnerability coverage under a defined review budget.

## Data preparation required before publication
- Obtain versioned NVD CVE JSON snapshots.
- Obtain dated EPSS scores and document the score date.
- Obtain dated CISA KEV catalogue snapshots.
- Validate CVE identifiers, CVSS versions, affected products and KEV status.
- Construct synthetic asset inventories and document generation rules.
- Retain complete reference records and generated defect masks.
- Label fields as REAL_PUBLIC, SYNTHETIC or DERIVED.

## Experimental design
Compare complete reference context with controlled missing, stale, conflicting and mixed defects. Vary defect rates, field types and random seeds. Keep the reference inventory fixed for paired comparisons.

## Baselines
CVSS-only, EPSS-only, KEV rules, combined conventional score, context-aware model where labels support training, and uncertainty-aware scenario ranking.

## Metrics
Precision@K, Recall@K, NDCG@K, risk capture, Top-K overlap, Kendall tau, Spearman rho, Top-K inclusion probability, rank standard deviation, review coverage, review precision and review workload.

## Threats to validity
Synthetic defect mechanisms may not match enterprise inventory error distributions. A chosen scoring function can influence ranking movement. EPSS and KEV snapshots must be time-aligned to avoid leakage. KEV is not a complete ground-truth exploit label. Report all assumptions and negative findings.
