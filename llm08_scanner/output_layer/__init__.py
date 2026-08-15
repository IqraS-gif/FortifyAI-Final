"""
llm08_scanner.output_layer
===========================
Output Layer — report generation, visualization, and remediation mapping.

Modules:
    report_builder      — Assembles JSON report from all ModuleResult objects (Phase 6)
    pdf_exporter        — reportlab PDF from JSON report (Phase 6)
    heatmap_visualizer  — UMAP 2D projection, Plotly HTML + matplotlib PNG (Phase 6)
    remediation_mapper  — Maps findings → OWASP LLM08 checklist + fix guidance (Phase 6)

All output artifacts are standalone — no live session required to read them.
"""
