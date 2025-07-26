import typer
import json
from rich import print
from generator.incident_factory import (
    generate_phishing_incident,
    generate_bruteforce_incident,
    generate_malware_incident,
    generate_ransomware_incident,
    generate_data_exfiltration_incident
)

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
        elif type == "bruteforce":
            incident = generate_bruteforce_incident()
        elif type == "malware":
            incident = generate_malware_incident()
        elif type == "ransomware":
            incident = generate_ransomware_incident()
        elif type == "data_exfiltration":
            incident = generate_data_exfiltration_incident()
        else:
            print(f"[bold red]Incident type '{type}' not implemented yet.[/]")
            return

        incidents.append(incident)

    print(json.dumps(incidents, indent=2))

if __name__ == "__main__":
    app()