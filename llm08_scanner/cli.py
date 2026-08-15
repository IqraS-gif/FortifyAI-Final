"""
llm08_scanner.cli
=================
Click-based command-line interface for the LLM08 Security Scanner.

Commands:
    scan      Run the full scanner against a configured vector DB
    validate  Validate a config file without running a scan
    version   Print scanner version

Implementation: Phase 7 (full integration). Stubs defined here in Phase 0.
"""

import sys
import click


@click.group()
@click.version_option(package_name="llm08_scanner")
def cli() -> None:
    """LLM08 Vector & Embedding Security Scanner.

    Automated penetration-testing framework for OWASP LLM08 weaknesses
    in RAG (Retrieval-Augmented Generation) pipelines.
    """


@cli.command()
@click.option(
    "--config",
    "-c",
    required=True,
    type=click.Path(exists=True, readable=True, resolve_path=True),
    help="Path to the scanner config YAML file.",
)
@click.option(
    "--output-dir",
    "-o",
    default=None,
    type=click.Path(resolve_path=True),
    help="Override the output directory for reports and heatmaps.",
)
@click.option(
    "--modules",
    "-m",
    multiple=True,
    default=["all"],
    help=(
        "Modules to run. Specify multiple times for a subset. "
        "Options: all, probe, acl_fuzzer, inversion, poisoning, drift, "
        "dp_noise, acl_sim, collision. Default: all"
    ),
)
def scan(config: str, output_dir: str | None, modules: tuple[str, ...]) -> None:
    """Run the full security scan against the configured vector database.

    Executes all enabled scanner modules in sequence, aggregates findings
    into a risk score, and writes JSON + PDF report and heatmap to disk.

    Implementation: Phase 7 (end-to-end integration). Not yet implemented.
    """
    # Implementation added in Phase 7 after all modules are individually verified.
    click.echo("ERROR: 'scan' command not yet implemented. Phase 7 pending.", err=True)
    sys.exit(1)


@cli.command()
@click.argument("config_path", type=click.Path(exists=True, readable=True, resolve_path=True))
def validate(config_path: str) -> None:
    """Validate a config YAML file against the JSON Schema.

    Exits 0 if the config is valid, 1 if it is not.
    Does NOT connect to the vector database.

    Implementation: Phase 1 (config_loader module). Not yet implemented.
    """
    click.echo("ERROR: 'validate' command not yet implemented. Phase 1 pending.", err=True)
    sys.exit(1)


@cli.command()
def version() -> None:
    """Print the scanner version and exit."""
    from llm08_scanner import __version__
    click.echo(f"llm08-scanner version {__version__}")


if __name__ == "__main__":
    cli()
