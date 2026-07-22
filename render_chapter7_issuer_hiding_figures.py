from __future__ import annotations

import argparse
import math
import os
import re
import tempfile
from pathlib import Path

_BASE_DIR = Path(__file__).resolve().parent
_MPLCONFIGDIR = Path(tempfile.gettempdir()) / "xiuzheng-matplotlib-cache"
_MPLCONFIGDIR.mkdir(exist_ok=True)
os.environ.setdefault("MPLCONFIGDIR", str(_MPLCONFIGDIR))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import pandas as pd
import seaborn as sns


BASE_DIR = _BASE_DIR
WORKSPACE_ROOT = BASE_DIR.parents[2]
DEFAULT_RESULTS_DIR = BASE_DIR / "results" / "issuer_hiding_20260610"
DEFAULT_OUT_DIR = WORKSPACE_ROOT / "7" / "7-re-pic"

TOKENS = {
    "surface": "#FCFCFD",
    "panel": "#FFFFFF",
    "ink": "#1F2430",
    "muted": "#6F768A",
    "grid": "#E6E8F0",
    "axis": "#D7DBE7",
}

COLORS = {
    "blue": "#5477C4",
    "gold": "#B8A037",
    "orange": "#CC6F47",
    "olive": "#71B436",
    "pink": "#BD569B",
    "grey": "#7A828F",
    "light_blue": "#A3BEFA",
    "light_orange": "#F0986E",
    "light_gold": "#FFE15B",
    "light_olive": "#A3D576",
    "light_pink": "#F390CA",
}


def configure_style() -> None:
    plt.rcParams.update(
        {
            "figure.facecolor": TOKENS["surface"],
            "axes.facecolor": TOKENS["panel"],
            "axes.edgecolor": TOKENS["axis"],
            "axes.labelcolor": TOKENS["ink"],
            "axes.titlecolor": TOKENS["ink"],
            "xtick.color": TOKENS["ink"],
            "ytick.color": TOKENS["ink"],
            "font.family": ["Segoe UI", "DejaVu Sans", "Arial", "sans-serif"],
            "font.size": 8.8,
            "axes.titlesize": 10.2,
            "axes.labelsize": 9.6,
            "legend.fontsize": 7.8,
            "figure.titlesize": 14,
        }
    )
    sns.set_theme(style="whitegrid")


def style_axis(ax, *, xgrid: bool = False, ygrid: bool = True) -> None:
    ax.set_facecolor(TOKENS["panel"])
    ax.grid(False)
    if ygrid:
        ax.grid(axis="y", color=TOKENS["grid"], linewidth=0.8)
    if xgrid:
        ax.grid(axis="x", color=TOKENS["grid"], linewidth=0.8)
    for side in ["top", "right"]:
        ax.spines[side].set_visible(False)
    for side in ["left", "bottom"]:
        ax.spines[side].set_color(TOKENS["axis"])
        ax.spines[side].set_linewidth(0.9)
    ax.tick_params(axis="both", labelsize=8.4)


def annotate_top_line(ax, xs, ys, color: str) -> None:
    for x, y in zip(xs, ys):
        ax.annotate(
            f"{y:.1f}",
            xy=(x, y),
            xytext=(0, 8),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=7.0,
            color=color,
            bbox={
                "boxstyle": "round,pad=0.18",
                "facecolor": TOKENS["panel"],
                "edgecolor": "none",
                "alpha": 0.92,
            },
        )


def add_panel_caption(ax, caption: str, *, y: float = -0.27) -> None:
    ax.text(
        0.5,
        y,
        caption,
        transform=ax.transAxes,
        ha="center",
        va="top",
        fontsize=10.2,
        fontweight="bold",
        color=TOKENS["ink"],
        clip_on=False,
    )


def run_count_from_experiment_id(experiment_id: str) -> int:
    match = re.search(r"-(\d+)runs$", str(experiment_id))
    return int(match.group(1)) if match else 0


def select_experiment_id(wide: pd.DataFrame, prefix: str) -> str:
    experiment_ids = [
        str(experiment_id)
        for experiment_id in wide["experiment_id"].dropna().unique()
        if str(experiment_id).startswith(prefix)
    ]
    if not experiment_ids:
        raise ValueError(f"No experiment_id starts with {prefix!r}")
    return max(experiment_ids, key=lambda experiment_id: (run_count_from_experiment_id(experiment_id), experiment_id))


def has_numeric_values(frame: pd.DataFrame, column: str) -> bool:
    return column in frame.columns and pd.to_numeric(frame[column], errors="coerce").notna().any()


def metric_column(wide: pd.DataFrame, component: str, suffix: str = "trimmed_mean_ms") -> str:
    fallback = f"{component}_{suffix}"
    preferred_columns = {
        "mean_ms": [f"{component}_round_mean_ms"],
        "trimmed_mean_ms": [
            f"{component}_batch_trimmed_mean_ms",
            f"{component}_round_trimmed_mean_ms",
        ],
    }.get(suffix, [])
    for preferred in preferred_columns:
        if has_numeric_values(wide, preferred):
            return preferred
    if has_numeric_values(wide, fallback):
        return fallback
    raise ValueError(f"Missing metric column for {component}_{suffix}")


def metric_axis_label(column: str) -> str:
    if column.endswith("_batch_trimmed_mean_ms"):
        return "Batch-trimmed mean (ms)"
    if column.endswith("_round_trimmed_mean_ms"):
        return "Per-batch trimmed mean (ms)"
    return "5% trimmed mean time (ms)"


def padded_axis_limit(values, *, minimum: float = 10.0, step: float = 10.0, pad: float = 1.15) -> float:
    finite_values = [float(value) for value in values if not pd.isna(value)]
    if not finite_values:
        return minimum
    upper = max(max(finite_values) * pad, minimum)
    return math.ceil(upper / step) * step


def render_ourscheme_scalability(wide: pd.DataFrame, output_dir: Path = DEFAULT_OUT_DIR) -> Path:
    fig, axes = plt.subplots(1, 3, figsize=(18.2, 5.05), dpi=180)

    k_experiment_id = select_experiment_id(wide, "issuer-hiding-k-axis-")
    q_experiment_id = select_experiment_id(wide, "issuer-hiding-q-axis-")
    max_experiment_id = select_experiment_id(wide, "issuer-hiding-max-k30-q24-")

    k_axis = wide[wide["experiment_id"].eq(k_experiment_id)].copy()
    k_axis = k_axis.sort_values("k")
    q_axis = wide[wide["experiment_id"].eq(q_experiment_id)].copy()
    q_axis = q_axis.sort_values("q_internal")
    max_row = wide[wide["experiment_id"].eq(max_experiment_id)].iloc[0]

    line_series = [
        ("Full verify", metric_column(wide, "verifyPresentationPayload_total_real"), COLORS["pink"], "D"),
        ("Present gen.", metric_column(wide, "presentTotal"), COLORS["gold"], "o"),
        ("Compute apk_U", metric_column(wide, "computeUserApk"), COLORS["orange"], "v"),
        ("Agg. PKs", metric_column(wide, "aggregatePublicKeys"), COLORS["olive"], "^"),
    ]
    y_axis_label = metric_axis_label(line_series[0][1])

    ax = axes[0]
    handles = []
    labels = []
    for label, col, color, marker in line_series:
        (line,) = ax.plot(
            k_axis["k"],
            k_axis[col],
            label=label,
            color=color,
            marker=marker,
            linewidth=1.9,
            markersize=4.2,
        )
        handles.append(line)
        labels.append(label)
    annotate_top_line(
        ax,
        k_axis["k"],
        k_axis[line_series[0][1]],
        COLORS["pink"],
    )
    ax.set_xlabel("Attribute count (k)")
    ax.set_ylabel(y_axis_label)
    ax.set_xticks(k_axis["k"].tolist())
    ax.set_ylim(0, padded_axis_limit(pd.concat([k_axis[col] for _, col, _, _ in line_series])))
    style_axis(ax)
    add_panel_caption(ax, "(a) Time vs attributes")

    ax = axes[1]
    for label, col, color, marker in line_series:
        (line,) = ax.plot(
            q_axis["q_internal"],
            q_axis[col],
            label=label,
            color=color,
            marker=marker,
            linewidth=1.8,
            markersize=4.0,
        )
    annotate_top_line(
        ax,
        q_axis["q_internal"],
        q_axis[line_series[0][1]],
        COLORS["pink"],
    )
    ax.set_xlabel("Internal contributions (q_internal)")
    ax.set_ylabel(y_axis_label)
    ax.set_xticks(q_axis["q_internal"].tolist())
    ax.set_ylim(0, padded_axis_limit(pd.concat([q_axis[col] for _, col, _, _ in line_series])))
    style_axis(ax)
    add_panel_caption(ax, "(b) Time vs internal contributions")

    components = [
        (
            "Full presentation verify",
            float(max_row[metric_column(wide, "verifyPresentationPayload_total_real")]),
            COLORS["pink"],
        ),
        ("Present generation", float(max_row[metric_column(wide, "presentTotal")]), COLORS["gold"]),
        (
            "Verify TA certificate",
            float(max_row[metric_column(wide, "verifyRandomizedTACredential_real")]),
            COLORS["light_orange"],
        ),
        ("Verify OR proof", float(max_row[metric_column(wide, "verifyORProof_real")]), COLORS["orange"]),
        (
            "Verifier simulation",
            float(max_row[metric_column(wide, "simulatePresentationPayloadByVerifier")]),
            COLORS["grey"],
        ),
        (
            "Verify blinded credential",
            float(max_row[metric_column(wide, "verifyBlindedAggregateCredential_real")]),
            COLORS["light_olive"],
        ),
        ("Local issuance work", float(max_row[metric_column(wide, "issueCredential")]), COLORS["blue"]),
        (
            "Aggregate public keys",
            float(max_row[metric_column(wide, "aggregatePublicKeys")]),
            COLORS["light_blue"],
        ),
        ("Compute apk_U", float(max_row[metric_column(wide, "computeUserApk")]), COLORS["light_blue"]),
        ("Generate TA certificate", float(max_row[metric_column(wide, "TACert")]), COLORS["light_pink"]),
    ]
    components = sorted(components, key=lambda item: item[1], reverse=True)

    ax = axes[2]
    y_positions = list(range(len(components)))
    ax.barh(
        y_positions,
        [value for _, value, _ in components],
        color=[color for _, _, color in components],
        edgecolor=TOKENS["axis"],
        linewidth=0.8,
    )
    ax.set_yticks(y_positions)
    ax.set_yticklabels([name for name, _, _ in components], fontsize=7.6)
    ax.invert_yaxis()
    ax.set_xlabel(y_axis_label)
    ax.set_xlim(0, padded_axis_limit([value for _, value, _ in components], minimum=20.0))
    style_axis(ax, xgrid=True, ygrid=False)
    add_panel_caption(ax, "(c) Major component costs at max parameters")
    for yi, (_, value, _) in enumerate(components):
        ax.text(value + 0.65, yi, f"{value:.1f}", va="center", ha="left", fontsize=7.5, color=TOKENS["ink"])

    # Shared legend stays above the plot area so it cannot cover the lines.
    fig.legend(
        handles,
        labels,
        loc="upper left",
        bbox_to_anchor=(0.055, 0.975),
        frameon=False,
        ncol=4,
        handlelength=1.8,
        columnspacing=1.5,
    )

    fig.subplots_adjust(left=0.055, right=0.985, top=0.865, bottom=0.255, wspace=0.38)
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / "fig_7_1_ourscheme_scalability_components_en.png"
    fig.savefig(output, dpi=300, bbox_inches="tight", facecolor=TOKENS["surface"])
    plt.close(fig)
    return output


def _baseline_float(row: pd.Series, field: str) -> float:
    value = row.get(field)
    if pd.isna(value) or str(value).strip() == "":
        return math.nan
    return float(value)


def render_issuer_hiding_comparison(
    wide: pd.DataFrame, baselines: pd.DataFrame, output_dir: Path = DEFAULT_OUT_DIR
) -> Path:
    max_experiment_id = select_experiment_id(wide, "issuer-hiding-max-k30-q24-")
    max_row = wide[wide["experiment_id"].eq(max_experiment_id)].iloc[0]
    comp_rows = [
        {
            "scheme": "OurScheme",
            "public_kib": float(max_row["apk_user_visible_bytes"]) / 1024,
            "transcript_kib": float(max_row["transcript_bytes_compact"]) / 1024,
            "verify_ms": float(max_row[metric_column(wide, "verifyPresentationPayload_total_real")]),
        }
    ]

    name_map = {
        "Katz-Sefranek 2026 BBS issuer hiding": "Katz-Sefranek 2026",
        "Sanders-Traore 2024 PS issuer hiding": "Sanders-Traore 2024",
        "Bobolz et al. 2021 issuer-hiding ABC": "Bobolz et al. 2021",
        "Bosk et al. 2022 HIAC": "Bosk et al. 2022",
        "Elkhiyaoui et al. 2021 one-out-of-many baseline": "Elkhiyaoui et al. 2021",
    }
    baseline_slice = baselines[(baselines["k"].eq(30)) & (baselines["issuer_set_size_public"].eq(24))]
    for _, row in baseline_slice.iterrows():
        if row["scheme"] not in name_map:
            continue
        comp_rows.append(
            {
                "scheme": name_map[row["scheme"]],
                "public_kib": _baseline_float(row, "user_visible_public_material_bytes") / 1024,
                "transcript_kib": _baseline_float(row, "presentation_transcript_bytes") / 1024,
                "verify_ms": _baseline_float(row, "verify_time_ms_est"),
            }
        )

    order = [
        "OurScheme",
        "Katz-Sefranek 2026",
        "Sanders-Traore 2024",
        "Bobolz et al. 2021",
        "Bosk et al. 2022",
        "Elkhiyaoui et al. 2021",
    ]
    comp = pd.DataFrame(comp_rows)
    comp["scheme"] = pd.Categorical(comp["scheme"], categories=order, ordered=True)
    comp = comp.sort_values("scheme")

    fig, axes = plt.subplots(1, 3, figsize=(18.2, 4.75), dpi=180)

    bar_colors = {
        "OurScheme": COLORS["blue"],
        "Katz-Sefranek 2026": COLORS["light_blue"],
        "Sanders-Traore 2024": COLORS["orange"],
        "Bobolz et al. 2021": COLORS["grey"],
        "Bosk et al. 2022": COLORS["gold"],
        "Elkhiyaoui et al. 2021": COLORS["pink"],
    }

    def horizontal_bar(ax, data: pd.DataFrame, value_col: str, caption: str, xlabel: str, *, log: bool = False, xmax=None) -> None:
        chart_data = data.dropna(subset=[value_col]).copy()
        chart_data = chart_data.sort_values(value_col, ascending=True)
        labels = chart_data["scheme"].astype(str)
        values = chart_data[value_col]
        ax.barh(
            labels,
            values,
            color=[bar_colors[label] for label in labels],
            edgecolor=TOKENS["axis"],
            linewidth=0.8,
        )
        ax.set_xlabel(xlabel)
        if log:
            ax.set_xscale("log")
            ax.xaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _pos: f"{x:g}"))
            ax.set_xlim(0.7, xmax or values.max() * 1.8)
        elif xmax:
            ax.set_xlim(0, xmax)
        else:
            ax.set_xlim(0, values.max() * 1.23)
        style_axis(ax, xgrid=True, ygrid=False)
        ax.tick_params(axis="y", labelsize=7.7)
        max_value = values.max()
        for ytick, value in enumerate(values):
            xpos = value * 1.10 if log else value + max_value * 0.025
            ax.text(xpos, ytick, f"{value:.1f}", va="center", ha="left", fontsize=7.5, color=TOKENS["ink"])
        add_panel_caption(ax, caption)

    horizontal_bar(axes[0], comp, "public_kib", "(a) User-visible public material", "Size (KiB, log scale)", log=True, xmax=300)
    horizontal_bar(axes[1], comp, "verify_ms", "(b) Presentation verification time", "Time (ms)")
    horizontal_bar(axes[2], comp, "transcript_kib", "(c) Presentation transcript size", "Size (KiB)", xmax=10.5)

    fig.subplots_adjust(left=0.10, right=0.985, top=0.94, bottom=0.255, wspace=0.52)
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / "fig_7_2_issuer_hiding_comparison_en.png"
    fig.savefig(output, dpi=300, bbox_inches="tight", facecolor=TOKENS["surface"])
    plt.close(fig)
    return output


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Render Chapter 7 issuer-hiding figures.")
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS_DIR)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    configure_style()
    wide = pd.read_csv(args.results_dir / "ours_summary_wide.csv")

    outputs = [
        render_ourscheme_scalability(wide, args.out_dir),
    ]
    baselines_path = args.results_dir / "issuer_hiding_baselines.csv"
    if baselines_path.exists():
        baselines = pd.read_csv(baselines_path)
        outputs.append(render_issuer_hiding_comparison(wide, baselines, args.out_dir))
    for output in outputs:
        print(output.resolve())


if __name__ == "__main__":
    main()
