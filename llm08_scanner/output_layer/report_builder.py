"""
llm08_scanner.output_layer.report_builder
===========================================
Orchestrates the output generation process.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import json
import dataclasses

from llm08_scanner.core.scoring_engine import OverallRiskScore
from llm08_scanner.output_layer.pdf_exporter import export_pdf

class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, o: Any) -> Any:
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        if hasattr(o, "item"):
            return o.item()
        return super().default(o)

log = logging.getLogger(__name__)


class ReportBuilder:
    def __init__(
        self,
        overall_score: OverallRiskScore,
        unique_tech_results: dict[str, Any],
        heatmap_path: str | None = None,
    ) -> None:
        self.overall_score = overall_score
        self.unique_tech_results = unique_tech_results
        self.heatmap_path = heatmap_path

    def build(self, output_dir: str = ".") -> str | None:
        """
        Builds the final PDF report. Returns the file path if successful.
        """
        timestamp_clean = self.overall_score.scan_timestamp.replace(":", "").replace("-", "").replace(".", "_")
        filename = f"llm08_scan_report_{timestamp_clean}.pdf"
        filepath = os.path.join(output_dir, filename)

        json_filename = f"llm08_scan_report_{timestamp_clean}.json"
        json_filepath = os.path.join(output_dir, json_filename)
        
        report_data = {
            "overall_score": self.overall_score,
            "unique_tech_results": self.unique_tech_results,
            "heatmap_path": self.heatmap_path,
        }
        try:
            with open(json_filepath, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2, cls=EnhancedJSONEncoder)
            log.info("Successfully generated JSON report at %s", json_filepath)
        except Exception as e:
            log.error("Failed to generate JSON report: %s", e)

        success = export_pdf(
            filepath=filepath,
            overall_score=self.overall_score,
            unique_tech_results=self.unique_tech_results,
            heatmap_path=self.heatmap_path,
        )

        if success:
            log.info("Successfully generated report at %s", filepath)
            return filepath
        else:
            log.error("Failed to generate PDF report.")
            return None
