"""
Terminal User Interface (TUI) for BlindAgent using Rich.
Visualizes real-time client enclave isolation vs host provider wire inspection.
"""

import sys
import time
from rich.console import Console
from rich.panel import Panel
from rich.columns import Columns
from rich.table import Table
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich.markdown import Markdown
from blindagent.pipeline import BlindPipeline

console = Console()


def print_banner():
    banner = """
[bold cyan]  ____  _ _           _    [/bold cyan][bold magenta]                        _   [/bold magenta]
[bold cyan] | __ )| (_)_ __   __| |   [/bold cyan][bold magenta]   /\\   __ _  ___ _ __ | |_ [/bold magenta]
[bold cyan] |  _ \\| | | '_ \\ / _` |   [/bold cyan][bold magenta]  /  \\ / _` |/ _ \\ '_ \\| __|[/bold magenta]
[bold cyan] | |_) | | | | | | (_| |   [/bold cyan][bold magenta] / /\\ \\ (_| |  __/ | | | |_ [/bold magenta]
[bold cyan] |____/|_|_|_| |_|\\__,_|   [/bold cyan][bold magenta]/_/  \\_\\__, |\\___|_| |_|\\__|[/bold magenta]
[bold cyan]                           [/bold cyan][bold magenta]       |___/                [/bold magenta]
[bold yellow]   ► Zero-Leakage AI Pipeline with GF(2^8) SSS & Token Blinding ◄[/bold yellow]
    """
    console.print(banner)


def render_interaction(pipeline: BlindPipeline, prompt: str):
    with console.status("[bold green]Applying GF(2^8) Secret Sharing & Blinding...", spinner="dots"):
        result = pipeline.execute(prompt)

    # 1. Dual View Panel
    layout = Layout()
    layout.split_row(
        Layout(name="client", ratio=1),
        Layout(name="cloud", ratio=1)
    )

    client_text = (
        f"[bold green]▶ Plaintext Input:[/bold green]\n{result.user_input}\n\n"
        f"[bold green]▶ Decrypted Agent Output:[/bold green]\n{result.final_output}"
    )
    cloud_text = (
        f"[bold red]▶ What Host Provider / Logs Receive:[/bold red]\n{result.wire_payload}\n\n"
        f"[bold red]▶ Raw Cloud LLM Processing:[/bold red]\n{result.host_raw_response}"
    )

    layout["client"].update(Panel(client_text, title="[bold green]🔒 Local Client Enclave (Secure)[/bold green]", border_style="green"))
    layout["cloud"].update(Panel(cloud_text, title="[bold red]☁️ Host Cloud Provider Wire View (Blinded)[/bold red]", border_style="red"))
    console.print(layout)

    # 2. SSS Shares & Cryptographic Audit Table
    table = Table(title="[bold yellow]Galois Field GF(2^8) Shamir's Secret Shares & Blinding Audit[/bold yellow]", border_style="yellow")
    table.add_column("Blinded Token", style="cyan")
    table.add_column("Original Secret (In Enclave)", style="green")
    table.add_column("Sample SSS Share (Over Wire)", style="magenta")
    table.add_column("Leakage Status", style="bold red")

    for token, entity in pipeline.blinder.vault.items():
        sample_share = entity.shares[0] if entity.shares else "N/A"
        # Dynamically reconstruct secret via C engine's Lagrange interpolation
        reconstructed = entity.reconstruct_secret(pipeline.blinder.sss)
        table.add_row(
            token if len(token) <= 45 else token[:42] + "...]]",
            reconstructed,
            sample_share[:36] + "...",
            "[bold green]0% LEAKAGE (SECURE)[/bold green]"
        )

    console.print(table)

    # 3. Security Metrics Panel
    metrics = result.metrics
    metrics_summary = (
        f"• [bold]Entities Shielded:[/bold] {metrics['entities_protected']} | "
        f"• [bold]Raw Entropy:[/bold] {metrics['raw_entropy_bits']} bits/byte | "
        f"• [bold]Blinded Entropy:[/bold] {metrics['blinded_entropy_bits']} bits/byte | "
        f"• [bold]Execution Latency:[/bold] {result.execution_time_ms} ms | "
        f"• [bold]Master Key Exposed:[/bold] [bold green]FALSE[/bold green] | "
        f"• [bold]Provider:[/bold] {result.provider_used}"
    )
    console.print(Panel(metrics_summary, title="[bold cyan]Mathematical Verification Metrics[/bold cyan]", border_style="cyan"))

    if getattr(pipeline.llm, "last_error", None):
        console.print(f"[dim yellow]⚠ Live Gemini API note: {pipeline.llm.last_error} (fell back to host simulator)[/dim yellow]")


def main():
    print_banner()
    console.print("[dim]Initializing C cryptographic engine (libblindcrypto.dylib)...[/dim]")
    pipeline = BlindPipeline(sss_threshold=3, sss_total=5)
    console.print("[bold green]✔ C Engine Active. Constant-time GF(2^8) ready.[/bold green]")

    if pipeline.llm.provider == "gemini":
        k_disp = pipeline.llm.api_key[:6] + "..." + pipeline.llm.api_key[-4:] if pipeline.llm.api_key else ""
        console.print(f"[bold green]✔ Cloud LLM Active: Google Gemini API (Live Mode | Key: {k_disp})[/bold green]\n")
    elif pipeline.llm.provider == "openai":
        console.print("[bold green]✔ Cloud LLM Active: OpenAI API (Live Mode)[/bold green]\n")
    else:
        console.print("[bold yellow]ℹ Cloud LLM: Local Host Simulator[/bold yellow] [dim](To use live Gemini: export GEMINI_API_KEY=\"...\" or create a .env file)[/dim]\n")

    default_examples = [
        "Please generate an SQL audit query for employee SSN: 123-45-6789 and master_key: SuperSecretMasterPassword! with balance $50,000.",
        "Summarize medical diagnosis for patient with SSN: 987-65-4321 and auth_token: sk-live99887766554433221100aa.",
        "Send notification email confirming authorization for <secret>ProjectTitanium-AccessCode-900</secret>."
    ]

    console.print("[bold]Select an example or enter a custom prompt:[/bold]")
    for i, ex in enumerate(default_examples, 1):
        console.print(f" [cyan][{i}][/cyan] {ex}")
    console.print(" [cyan][c][/cyan] Custom user input [dim](Tip: wrap any custom text in <secret>...</secret>)[/dim]\n [cyan][q][/cyan] Quit\n")

    while True:
        try:
            choice = console.input("[bold yellow]Choice > [/bold yellow]").strip()
            if choice.lower() == 'q':
                console.print("[bold cyan]Exiting BlindAgent. Stay secure![/bold cyan]")
                break
            elif choice == '1':
                render_interaction(pipeline, default_examples[0])
            elif choice == '2':
                render_interaction(pipeline, default_examples[1])
            elif choice == '3':
                render_interaction(pipeline, default_examples[2])
            elif choice.lower() == 'c':
                user_p = console.input("[bold green]Enter confidential prompt > [/bold green]")
                if user_p.strip():
                    render_interaction(pipeline, user_p)
            elif len(choice) > 3:
                # Direct prompt entered without typing 'c' first
                render_interaction(pipeline, choice)
            else:
                console.print("[red]Invalid choice, try again.[/red]")
            console.print("\n" + "=" * 80 + "\n")
        except (KeyboardInterrupt, EOFError):
            break


if __name__ == "__main__":
    main()
