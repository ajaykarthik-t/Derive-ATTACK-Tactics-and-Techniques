import pandas as pd
import requests
from bs4 import BeautifulSoup
import json
import random
from datetime import datetime, timedelta

def fetch_mitre_data():
    """Fetch MITRE ATT&CK data from their Enterprise API"""
    enterprise_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    response = requests.get(enterprise_url)
    return response.json()

def extract_techniques(mitre_data):
    """Extract techniques from MITRE data"""
    techniques = []
    for obj in mitre_data['objects']:
        if obj['type'] == 'attack-pattern':
            technique = {
                'technique_id': obj.get('external_references', [{}])[0].get('external_id', ''),
                'name': obj.get('name', ''),
                'description': obj.get('description', ''),
                'tactics': [phase['phase_name'] for phase in obj.get('kill_chain_phases', [])]
            }
            techniques.append(technique)
    return techniques

def generate_threat_report(techniques, num_incidents=100):
    """Generate synthetic threat report data"""
    reports = []
    
    for _ in range(num_incidents):
        # Select random number of techniques for this incident
        num_techniques = random.randint(1, 5)
        selected_techniques = random.sample(techniques, num_techniques)
        
        # Generate random date within last year
        date = datetime.now() - timedelta(days=random.randint(0, 365))
        
        # Create incident report
        report = {
            'date': date.strftime('%Y-%m-%d'),
            'incident_id': f'INC-{random.randint(10000, 99999)}',
            'severity': random.choice(['High', 'Medium', 'Low']),
            'techniques_used': [],
            'tactics_observed': [],
            'description': []
        }
        
        for technique in selected_techniques:
            report['techniques_used'].append(technique['technique_id'])
            report['tactics_observed'].extend(technique['tactics'])
            report['description'].append(technique['description'])
        
        report['tactics_observed'] = list(set(report['tactics_observed']))
        report['description'] = ' '.join(report['description'])
        reports.append(report)
    
    return reports

def main():
    # Fetch MITRE data
    print("Fetching MITRE ATT&CK data...")
    mitre_data = fetch_mitre_data()
    
    # Extract techniques
    print("Extracting techniques...")
    techniques = extract_techniques(mitre_data)
    
    # Generate synthetic threat reports
    print("Generating threat reports...")
    reports = generate_threat_report(techniques)
    
    # Convert to DataFrame and save
    df = pd.DataFrame(reports)
    df.to_csv('threat_reports.csv', index=False)
    print(f"Generated {len(df)} threat reports and saved to threat_reports.csv")

if __name__ == "__main__":
    main()