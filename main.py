import typer
import json
from rich import print
from generator.incident_factory import generate_phishing_incident

app = typer.Typer()

@app.command()
def generate(
    type: str = typer.Option("phishing", help="Type of incident to generate"),
    format: str = typer.Option("json", help="Output format"),
    count: int = typer.Option(1, help="Number of incidents to generate"),
    noise: bool = typer.Option(False, help="Include random noisy events"),
    correlated: bool = typer.Option(False, help="Generate correlated events")
):
    incidents = []

    for _ in range(count):
        if type == "phishing":
            incident = generate_phishing_incident()
        else:
            print(f"[bold red]Incident type '{type}' not implemented yet.[/]")
            return

        incidents.append(incident)

    print(json.dumps(incidents, indent=2))

if __name__ == "__main__":
    app()