"""Local temporary charts embedded in generated reports."""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

RISK_COLORS = {
    "low": "#2E8B57",
    "medium": "#D9A21B",
    "high": "#D66A1F",
    "critical": "#B42318",
    "unscored": "#8A96A0",
}


def risk_distribution_chart(distribution: dict[str, int], output: Path) -> None:
    """Create a compact horizontal risk-count chart."""
    labels = ["Low", "Medium", "High", "Critical", "Unscored"]
    keys = [label.lower() for label in labels]
    values = [distribution[key] for key in keys]
    figure, axis = plt.subplots(figsize=(5.2, 2.25), dpi=160)
    bars = axis.barh(labels[::-1], values[::-1], color=[RISK_COLORS[key] for key in keys[::-1]])
    axis.set_title("Contextual risk distribution", loc="left", fontsize=10, fontweight="bold")
    axis.set_xlabel("Findings", fontsize=8)
    axis.tick_params(labelsize=8)
    axis.spines[["top", "right", "left"]].set_visible(False)
    axis.grid(axis="x", alpha=0.2)
    axis.bar_label(bars, padding=3, fontsize=8)
    axis.set_xlim(0, max(values + [1]) * 1.25)
    figure.tight_layout()
    figure.savefig(output, bbox_inches="tight", facecolor="white")
    plt.close(figure)


def top_findings_chart(priorities: list[dict[str, object]], output: Path) -> None:
    """Create a compact chart of up to five highest contextual scores."""
    selected = priorities[:5]
    labels = [f"{item['asset_name']} | {item['vulnerability']}" for item in selected]
    values = [float(item["contextual_risk_score"] or 0) for item in selected]
    if not selected:
        labels = ["No open scored findings"]
        values = [0.0]
    labels = [_shorten(label, 34) for label in labels]
    figure, axis = plt.subplots(figsize=(5.2, 2.25), dpi=160)
    bars = axis.barh(labels[::-1], values[::-1], color="#197A83")
    axis.set_title("Top open contextual risks", loc="left", fontsize=10, fontweight="bold")
    axis.set_xlabel("Risk score (0-100)", fontsize=8)
    axis.set_xlim(0, 100)
    axis.tick_params(labelsize=7)
    axis.spines[["top", "right", "left"]].set_visible(False)
    axis.grid(axis="x", alpha=0.2)
    axis.bar_label(bars, fmt="%.2f", padding=3, fontsize=7)
    figure.tight_layout()
    figure.savefig(output, bbox_inches="tight", facecolor="white")
    plt.close(figure)


def _shorten(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 3] + "..."
