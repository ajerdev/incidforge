import typer
import json
from rich import print
import random 

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
    generate_noise_event
)

# app = typer.Typer()
# @app.command()

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
        elif type == "command_and_control":
            incident = generate_command_and_control_incident()
        elif type == "insider_threat":
            incident = generate_insider_threat_incident()
        elif type == "port_scanning":
            incident = generate_port_scanning_incident()
        elif type == "web_exploit":
            incident = generate_web_exploit_incident()
        elif type == "suspicious_powershell":
            incident = generate_suspicious_powershell_incident()
        else:
            print(f"[bold red]Incident type '{type}' not implemented yet.[/]")
            return    

        incidents.append(incident)

    if noise:
        noise_events = [generate_noise_event() for _ in range(random.randint(1, count))]
        incidents.extend(noise_events)
        random.shuffle(incidents)

    print(json.dumps(incidents, indent=2))

if __name__ == "__main__":
    #app()
    typer.run(generate)