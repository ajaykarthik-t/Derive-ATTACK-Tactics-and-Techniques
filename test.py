import pandas as pd
import random
from datetime import datetime, timedelta

def generate_test_files():
    """Generate 20 small test CSV files with different classifications"""
    
    # Define possible tactics and techniques
    tactics = ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 
              'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 
              'Collection', 'Command and Control']
              
    techniques = {
        'Initial Access': ['T1190', 'T1133', 'T1566'],
        'Execution': ['T1059', 'T1106', 'T1204'],
        'Persistence': ['T1098', 'T1136', 'T1505'],
        'Privilege Escalation': ['T1548', 'T1134', 'T1484'],
        'Defense Evasion': ['T1070', 'T1202', 'T1222'],
        'Credential Access': ['T1110', 'T1555', 'T1556'],
        'Discovery': ['T1087', 'T1082', 'T1083'],
        'Lateral Movement': ['T1021', 'T1091', 'T1210'],
        'Collection': ['T1114', 'T1115', 'T1119'],
        'Command and Control': ['T1071', 'T1105', 'T1572']
    }
    
    # Generate 20 different test files
    for i in range(20):
        # Select random primary tactic for this file
        primary_tactic = random.choice(tactics)
        
        # Generate 10-15 samples for each file
        num_samples = random.randint(10, 15)
        
        test_data = []
        for _ in range(num_samples):
            # Generate sample
            sample = {
                'date': (datetime.now() - timedelta(days=random.randint(0, 30))).strftime('%Y-%m-%d'),
                'incident_id': f'TEST-{i+1}-{random.randint(1000, 9999)}',
                'severity': random.choice(['High', 'Medium', 'Low']),
                'primary_tactic': primary_tactic,
                'technique_id': random.choice(techniques[primary_tactic]),
                'secondary_tactics': random.sample([t for t in tactics if t != primary_tactic], 
                                                k=random.randint(0, 2))
            }
            
            # Add secondary techniques
            secondary_techniques = []
            for tactic in sample['secondary_tactics']:
                secondary_techniques.append(random.choice(techniques[tactic]))
            sample['secondary_techniques'] = secondary_techniques
            
            test_data.append(sample)
        
        # Convert to DataFrame and save
        df = pd.DataFrame(test_data)
        df.to_csv(f'test_data_{i+1}.csv', index=False)
        print(f"Generated test_data_{i+1}.csv with focus on {primary_tactic}")

if __name__ == "__main__":
    generate_test_files()