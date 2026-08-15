# Visual Validation Task List

- [x] Navigate to http://localhost:5173/ and wait 6 seconds
- [x] Scroll to the very top and capture full screenshot (top_dashboard)
- [x] Scroll down ~600px and capture screenshot of Risk Summary gauge (risk_summary)
- [x] Scroll down ~400px and capture screenshot of Core Modules section (core_modules)
- [x] Scroll down ~600px and capture screenshot of Unique Tech section (unique_tech)
- [x] Scroll down ~600px and capture screenshot of Findings Explorer table (findings_explorer)
- [x] Scroll down to the bottom and capture screenshot of Heatmap & Export section (heatmap_and_export)
- [x] Document findings for each screenshot

## Detailed Findings

1. **Top Dashboard (`top_dashboard_1786791611823.png`)**
   - Header Bar: Shows "LLM08 Vector Security Scanner" (OWASP LLM08 · Qdrant Embedding Auditor) with a "Demo Mode" pill badge.
   - OWASP overview panel is present with 4 threat explainer cards (ACL/tenant isolation, Embedding inversion, Poisoning, Semantic drift/probing).
   - Scan Controls: Demo Mode is ON (orange toggle), showing banner "Demo Mode · Cached scan from 20260815T104138_661327+0000". Drodown lists "20260815T104138_661327+0000 — config_final.yaml [MEDIUM]".

2. **Risk Summary (`risk_summary_1786791618317.png`)**
   - Radial Gauge shows a clear score of `55` / 100 with label "MEDIUM Overall Risk Level".
   - Under the score: timestamp "20260815T104138_661327+0000" and engine version "v0.5.0".

3. **Core Modules Section (`core_modules_1786791624741.png`)**
   - Bar chart clearly renders scores for the 5 core modules:
     - ACL Fuzzer: 100
     - Inversion Tester: 20
     - Poisoning Simulator: 67
     - Drift Detector: 13
     - Probe Generator: 25
   - Core module cards render weights matching the report JSON (never hardcoded):
     - ACL Fuzzer: 100 (weight 30%), 38 findings
     - Inversion Tester: 20 (weight 20%), 72 findings
     - Poisoning Simulator: 67 (weight 25%), 3 findings
     - Drift Detector: 13 (weight 15%), 9 findings
     - Probe Generator: 25 (weight 10%), 10 findings
     - Weighted average = 55.2 (rounds to 55, matching the overall score).

4. **Unique Tech / Supplementary Analysis (`unique_tech_1786791630718.png` / `core_modules_1786791624741.png`)**
   - Clear banner stating "Does not affect the risk score" (per DD-010).
   - Cards display actual scores and findings preview:
     - DP Noise Injector: score 0.0, 2 findings (JSON format)
     - ACL Simulator: score 0.0, "No findings."
     - Collision Scorer: score 1.4 (value 1.408), 1 finding (JSON format)
     - Poison Classifier: score 5.6 (value 5.634), 71 findings (JSON format list)

5. **Findings Explorer (`findings_explorer_1786791639632.png` / `mid_findings_1786791648228.png`)**
   - Headings show "Findings Explorer 132 of 132 findings".
   - Search input and All Severities / All Modules filters are present.
   - Table rows correctly list findings from the active cached scan, e.g., Row 1-10 ACL Fuzzer (INFO severity, tenant_a summary), Row 11-20 (tenant_b summary), Row 21-28 (tenant_c summary), through Inversion Tester findings (INFO severity, numbered summaries 38-55).

6. **Heatmap & Export (`bottom_dashboard_1786791656292.png`)**
   - Vector Space Heatmap panel correctly displays the UMAP projection of all vectors.
   - The UMAP plot successfully loaded showing two clusters: one main cluster of blue dots (representing the collections `demo_shared_collection` and `demo_isolated_collection`), and a second cluster of red stars (representing the "Anomalous/Poisoned" vectors).
   - Export card shows the "Download Full PDF Report" button in blue with a page icon.
   - Footer contains: "LLM08 Vector Security Scanner · Phase 7 Complete · 69/69 tests passing".
