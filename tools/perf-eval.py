# Script to compare apt performance logs
#
# Copyright (C) 2026 Julian Andres Klode <jak@debian.org>
#
# SPDX-License-Identifier: GPL-2.0+

import sys
import typing

import pandas as pd

try:
    import rich
    import rich.table
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
            "std": df.std(),
            "cv (%)": df.std() / df.mean() * 100,
        }
    )

    # Summing up the rates doesn't make much sense, calculate the total rate instead
    for name, a, b in RATES:
        out.loc[name, "total"] = df[a].sum() / df[b].sum()
    return out


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

    table.add_column(style="bold")
    for column in out.columns:
        table.add_column(str(column), justify="right")

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
                row[i] = f"[green]{row[i]:.5e}[/green]"
            elif bot and (row[i] > top) and isinstance(out.columns[i], int):
                row[i] = f"[red]{row[i]:.5e}[/red]"
            elif isinstance(out.columns[i], str) and "%" in out.columns[i]:
                change = "change" in out.columns[i]
                if change and row[i] > 0:
                    row[i] = f"[red]{row[i]:.2f}[/red]"
                elif change and row[i] < 0:
                    row[i] = f"[green]{row[i]:.2f}[/green]"
                else:
                    row[i] = f"{row[i]:.2f}"
            else:
                row[i] = f"{row[i]:.5e}"

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

    for context in results:
        print_table(analyze_contexts(results[context]), title=context)


if __name__ == "__main__":
    main()
