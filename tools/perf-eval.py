# Script to compare apt performance logs
#
# Copyright (C) 2026 Julian Andres Klode <jak@debian.org>
#
# SPDX-License-Identifier: GPL-2.0+

import math
import sys
import typing

import numpy as np
import pandas as pd

try:
    import rich
    import rich.table
    import rich.text
except ImportError:
    rich = None  # type: ignore[assignment]


# Rate values to calculate. These have some special handling
RATES = [
    ("ipc", "instructions", "cpu_cycles"),
    ("cache_miss_rate", "cache_misses", "cache_references"),
    ("branch_miss_rate", "branch_misses", "branch_instructions"),
]


def read_file(file: str) -> pd.DataFrame:
    """Read a single APT performance file"""
    with open(file) as fd:
        df = pd.read_json(fd, lines=True)
    for name, a, b in RATES:
        df[name] = df[a] / df[b]
    return df


def extract_context(df: pd.DataFrame, context: str) -> pd.DataFrame:
    """Extract a single context from a APT performance file"""
    df = df[df["context"] == context]
    del df["context"]

    out = pd.DataFrame(
        {
            "total": df.sum(),
            "mean": df.mean(),
            "p-50": df.quantile(0.5),
            "p-90": df.quantile(0.9),
            "std": df.std(),
            "cv (%)": df.std() / df.mean() * 100,
        }
    )

    # Summing up the rates doesn't make much sense, calculate the total rate instead
    for name, a, b in RATES:
        out.loc[name, "total"] = df[a].sum() / df[b].sum()
    # Metrics whose samples are all zero carry no information
    out.loc[(df == 0).all()] = math.nan
    # Raw samples, for the significance test when comparing files
    out.attrs["samples"] = df
    return out


def hodges_lehmann_change(x: pd.Series, y: pd.Series) -> float:
    """Hodges–Lehmann estimate of the typical change from y to x, in percent.

    Median of the pairwise log-ratios log(x_j / y_i); the effect-size
    estimator conjugate to the Mann-Whitney U test (ranks are invariant
    under the log transform). Returns NaN if any sample is non-positive.
    """
    if (x <= 0).any() or (y <= 0).any():
        return math.nan
    lx = np.log(np.asarray(x, dtype=float))
    ly = np.log(np.asarray(y, dtype=float))
    return (math.exp(np.median(lx[:, None] - ly[None, :])) - 1) * 100


def mann_whitney_u(x: pd.Series, y: pd.Series) -> float:
    """Two-sided Mann-Whitney U test p-value.

    Rank-based test that two sets of samples are differently distributed
    (stochastic ordering); robust to outliers and non-normal data. Uses the
    normal approximation with continuity and tie correction.
    """
    n1, n2 = len(x), len(y)
    if n1 == 0 or n2 == 0:
        return math.nan
    values = np.concatenate([x, y])
    n = len(values)

    # Average ranks; tied values share the mean of their ranks
    sorter = np.argsort(values, kind="stable")
    ranks = np.empty(n)
    tie_term = 0.0
    i = 0
    while i < n:
        j = i
        while j + 1 < n and values[sorter[j + 1]] == values[sorter[i]]:
            j += 1
        ranks[sorter[i : j + 1]] = (i + j) / 2.0 + 1
        t = j - i + 1
        tie_term += t * t * t - t
        i = j + 1

    u = ranks[:n1].sum() - n1 * (n1 + 1) / 2.0
    u = max(u, n1 * n2 - u)
    var = n1 * n2 / 12.0 * ((n + 1) - tie_term / (n * (n - 1.0)))
    if var <= 0:
        # All values identical across both files
        return 1.0
    z = max((u - n1 * n2 / 2.0 - 0.5) / math.sqrt(var), 0.0)
    return math.erfc(z / math.sqrt(2.0))


def analyze_contexts(contexts: list[pd.DataFrame]) -> pd.DataFrame:
    """Compare a bunch of data frames or just return the data frame if a single one."""
    # Single frame, nothing to compare
    if len(contexts) == 1:
        return contexts[0]

    out = pd.DataFrame()
    for r in contexts:
        out[len(out.columns)] = r["mean"]

    # Use the total rate in a file rather than mean sample rate
    for i in range(len(contexts)):
        for name, _, _ in RATES:
            out.loc[name, i] = contexts[i].loc[name, "total"]

    if len(contexts) == 2:
        out["change (%)"] = out[1] / out[0] * 100 - 100
        # Per-file coefficient of variation, to judge run-to-run noise
        out["cv0 (%)"] = contexts[0]["cv (%)"]
        out["cv1 (%)"] = contexts[1]["cv (%)"]
        # Mann-Whitney U test between the two files' samples (rank based,
        # robust to outliers and non-normal data). For rate rows (ipc,
        # cache_miss_rate, branch_miss_rate) the columns 0/1 above show the
        # total rate, but the test uses the per-sample rates. Metrics that are
        # all zero in both files (NaN statistics, see extract_context) carry
        # no information, so their p-value is NaN as well.
        samples0 = contexts[0].attrs["samples"]
        samples1 = contexts[1].attrs["samples"]
        dead = contexts[0]["mean"].isna() & contexts[1]["mean"].isna()
        out["p-value"] = [
            mann_whitney_u(samples0[row], samples1[row])
            if not dead.get(row, False) and row in samples0 and row in samples1
            else math.nan
            for row in out.index
        ]
        # Hodges–Lehmann estimate of the typical change between the two files'
        # samples: the median of the pairwise log-ratios, i.e. the effect-size
        # estimator conjugate to the rank-based p-value above. For rate rows
        # (ipc, cache_miss_rate, branch_miss_rate) the columns 0/1 show the
        # total rate, but the estimate uses the per-sample rates.
        out["typical change (%)"] = [
            hodges_lehmann_change(samples1[row], samples0[row])
            if row in samples0 and row in samples1
            else math.nan
            for row in out.index
        ]
        # Empty columns to visually separate the two files and the change columns
        out[""] = ""
        out[" "] = ""
        out = out[
            [
                0,
                "cv0 (%)",
                "",
                1,
                "cv1 (%)",
                " ",
                "change (%)",
                "typical change (%)",
                "p-value",
            ]
        ]
    else:
        # Calculate statistics across the files
        out["mean"] = out.agg("mean", axis=1)
        out["std"] = out.agg("std", axis=1)
        out["cv (%)"] = out["std"] / out["mean"] * 100
    return out


def print_table(out: pd.DataFrame, *, title: str) -> None:
    """Render the table, either rich or with pure pandas"""
    if rich is None:
        print(f"{title}:")
        print(out)
        print()
        return

    table = rich.table.Table(title=title)

    # In two-file mode, group each file's columns under a "0"/"1" label on the
    # first column of the group, using a two-line header (rich has no spanning)
    two_file = "cv0 (%)" in out.columns

    def header(column: object) -> "str | rich.text.Text":
        if not two_file:
            return str(column)
        if isinstance(column, str) and not column.strip():
            return rich.text.Text("\n", justify="right")
        if isinstance(column, int):
            return rich.text.Text(f"{column}\nmean", justify="right")
        if isinstance(column, str) and column.startswith("cv"):
            return rich.text.Text("\ncv (%)", justify="right")
        if column == "change (%)":
            return rich.text.Text("mean\nΔ (%)", justify="right")
        if column == "typical change (%)":
            return rich.text.Text("typical\nΔ (%)", justify="right")
        return rich.text.Text(f"\n{column}", justify="right")

    table.add_column(style="bold")
    for column in out.columns:
        table.add_column(header(column), justify="right")

    # Check if we have a mean and std column to determine "normal" ranges
    try:
        mean_col: int | None = typing.cast(int, out.columns.get_loc("mean"))
        std_col: int | None = typing.cast(int, out.columns.get_loc("std"))
    except KeyError:
        mean_col = std_col = None

    for index, rowa in zip(out.index, out.values):
        top = rowa[mean_col] + rowa[std_col] if mean_col else None
        bot = rowa[mean_col] - rowa[std_col] if mean_col else None
        # Convert row array to list for manipulation
        row = list(rowa)
        for i in range(len(row)):
            if bot and (row[i] < bot) and isinstance(out.columns[i], int):
                row[i] = f"[green]{row[i]:.2e}[/green]"
            elif bot and (row[i] > top) and isinstance(out.columns[i], int):
                row[i] = f"[red]{row[i]:.2e}[/red]"
            elif isinstance(out.columns[i], str) and not out.columns[i].strip():
                row[i] = ""
            elif isinstance(out.columns[i], str) and "%" in out.columns[i]:
                change = "change" in out.columns[i]
                if change and row[i] > 0:
                    row[i] = f"[red]{row[i]:.2f}[/red]"
                elif change and row[i] < 0:
                    row[i] = f"[green]{row[i]:.2f}[/green]"
                else:
                    row[i] = f"{row[i]:.2f}"
            elif out.columns[i] == "p-value":
                p = row[i]
                if math.isnan(p):
                    row[i] = "nan"
                else:
                    text = f"{p:.1e}" if p < 0.001 else f"{p:.3f}"
                    if p < 0.001:
                        row[i] = f"[bold green]{text}[/bold green]"
                    elif p < 0.01:
                        row[i] = f"[green]{text}[/green]"
                    elif p < 0.05:
                        row[i] = f"[yellow]{text}[/yellow]"
                    else:
                        row[i] = text
            else:
                row[i] = f"{row[i]:.2e}"

        table.add_row(index, *row)

    rich.print(table)
    print()


def main() -> None:
    results: dict[str, list[pd.DataFrame]] = {}

    for file in sys.argv[1:]:
        df = read_file(file)
        for context in df["context"].unique():
            extracted = extract_context(df, context)
            try:
                results[context].append(extracted)
            except KeyError:
                results[context] = [extracted]

    for context, frames in results.items():
        print_table(analyze_contexts(frames), title=context)


if __name__ == "__main__":
    main()
