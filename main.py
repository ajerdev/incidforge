import typer
import json
from rich import print
import random 

from generator.utils import generate_random_email, generate_random_ip

from generator.incident_factory import (
    generate_phishing_incident,
    generate_bruteforce_incident,
    generate_malware_incident,
    generate_ransomware_incident,
    generate_data_exfiltration_incident,
    generate_command_and_control_incident,
    generate_insider_threat_incident,
    generate_port_scanning_incident,
    generate_web_exploit_incident,
    generate_suspicious_powershell_incident,
    generate_noise_event,
    generate_incident_by_type
)

# app = typer.Typer()
# @app.command()

def generate(
    type: str = typer.Option("phishing", help="Type of incident to generate"),
    format: str = typer.Option("json", help="Output format"),
    count: int = typer.Option(1, help="Number of incidents to generate"),
    noise: bool = typer.Option(False, help="Include random noisy events"),
    export: bool = typer.Option(False, help="Export incidents to file"),
    correlate: str = typer.Option(None, help="Second incident type to correlate with the primary one")
):
    incidents = []

    for _ in range(count):
        incident = generate_incident_by_type(type)
        incidents.append(incident)

        if correlate:
            shared_ip = incident.get("source_ip", generate_random_ip())
            shared_user = incident.get("target_user", generate_random_email())
            correlated_incident = generate_incident_by_type(correlate, ip=shared_ip, user=shared_user)
            incidents.append(correlated_incident)

    if noise:
        noise_events = [generate_noise_event() for _ in range(random.randint(1, count))]
        incidents.extend(noise_events)
        random.shuffle(incidents)

    incidents.sort(key=lambda x: x["timestamp"])
    print(json.dumps(incidents, indent=2))

    if export:
        from datetime import datetime
        import os

        os.makedirs("exports", exist_ok=True)

        now = datetime.now().strftime("%Y%m%d_%H%M")
        filename = f"exports/incidents_{now}_{count}{type}.json"

        with open(filename, "w") as f:
            json.dump(incidents, f, indent=2)

        print(f"[bold green]✔ Incidents exported to:[/] {filename}")


if __name__ == "__main__":
    #app()
    typer.run(generate)