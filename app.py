import streamlit as st
import pandas as pd
import numpy as np
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
import pickle
import plotly.express as px
import plotly.graph_objects as go
import requests
import json
import os
from datetime import datetime

class MitreData:
    """Class to handle MITRE ATT&CK data fetching and caching"""
    def __init__(self):
        self.techniques_data = self.load_mitre_data()
    
    def load_mitre_data(self):
        """Load or fetch MITRE ATT&CK data"""
        cache_file = 'mitre_cache.json'
        
        # Try to load from cache first
        if os.path.exists(cache_file):
            with open(cache_file, 'r') as f:
                return json.load(f)
        
        # If no cache, fetch from MITRE
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        response = requests.get(url)
        data = response.json()
        
        # Process and cache techniques
        techniques = {}
        for obj in data['objects']:
            if obj['type'] == 'attack-pattern':
                technique_id = obj.get('external_references', [{}])[0].get('external_id', '')
                if technique_id:
                    techniques[technique_id] = {
                        'name': obj.get('name', ''),
                        'description': obj.get('description', ''),
                        'tactics': [p['phase_name'] for p in obj.get('kill_chain_phases', [])],
                        'platforms': obj.get('x_mitre_platforms', []),
                        'detection': obj.get('x_mitre_detection', ''),
                        'mitigation': obj.get('x_mitre_mitigation', '')
                    }
        
        # Save to cache
        with open(cache_file, 'w') as f:
            json.dump(techniques, f)
        
        return techniques

class AttackAnalyzer:
    """Main analysis class for ATT&CK data"""
    def __init__(self):
        self.mitre_data = MitreData()
    
    def analyze_csv(self, df):
        """Analyze CSV data and return comprehensive results"""
        try:
            # Ensure date column is datetime
            df['date'] = pd.to_datetime(df['date'])
            
            results = {
                'summary': self.generate_summary(df),
                'technique_analysis': self.analyze_techniques(df),
                'tactic_analysis': self.analyze_tactics(df),
                'temporal_analysis': self.analyze_temporal_patterns(df),
                'risk_analysis': self.analyze_risk_patterns(df)
            }
            return results, None
        except Exception as e:
            return None, str(e)
    
    def generate_summary(self, df):
        """Generate summary statistics"""
        return {
            'total_incidents': len(df),
            'unique_techniques': df['technique_id'].nunique(),
            'unique_tactics': df['primary_tactic'].nunique(),
            'time_period': {
                'start': df['date'].min().strftime('%Y-%m-%d'),
                'end': df['date'].max().strftime('%Y-%m-%d')
            },
            'severity_distribution': df['severity'].value_counts().to_dict()
        }
    
    def analyze_techniques(self, df):
        """Analyze technique patterns"""
        technique_analysis = []
        
        for technique_id in df['technique_id'].unique():
            technique_data = self.mitre_data.techniques_data.get(technique_id, {})
            technique_incidents = df[df['technique_id'] == technique_id]
            
            analysis = {
                'technique_id': technique_id,
                'name': technique_data.get('name', 'Unknown'),
                'description': technique_data.get('description', 'No description available'),
                'count': len(technique_incidents),
                'severity_breakdown': technique_incidents['severity'].value_counts().to_dict(),
                'associated_tactics': technique_data.get('tactics', []),
                'platforms': technique_data.get('platforms', []),
                'detection': technique_data.get('detection', 'No detection guidance available'),
                'mitigation': technique_data.get('mitigation', 'No mitigation guidance available')
            }
            technique_analysis.append(analysis)
        
        return technique_analysis
    
    def analyze_tactics(self, df):
        """Analyze tactical patterns"""
        return [
            {
                'tactic': tactic,
                'count': len(tactic_incidents),
                'techniques_used': tactic_incidents['technique_id'].unique().tolist(),
                'severity_breakdown': tactic_incidents['severity'].value_counts().to_dict()
            }
            for tactic, tactic_incidents in df.groupby('primary_tactic')
        ]
    
    def analyze_temporal_patterns(self, df):
        """Analyze patterns over time"""
        # Group by date and count incidents
        daily_counts = df.groupby('date').size()
        
        # Analyze technique usage over time
        technique_evolution = df.groupby(['date', 'technique_id']).size().unstack(fill_value=0)
        
        return {
            'daily_counts': {date.strftime('%Y-%m-%d'): count 
                           for date, count in daily_counts.items()},
            'technique_evolution': {date.strftime('%Y-%m-%d'): techniques.to_dict() 
                                  for date, techniques in technique_evolution.iterrows()}
        }
    
    def analyze_risk_patterns(self, df):
        """Analyze risk patterns"""
        high_severity = df[df['severity'] == 'High']
        
        return {
            'high_severity_techniques': high_severity['technique_id'].value_counts().to_dict(),
            'critical_combinations': [
                {
                    'tactic': tactic,
                    'techniques': techniques['technique_id'].unique().tolist(),
                    'incident_count': len(techniques)
                }
                for tactic, techniques in high_severity.groupby('primary_tactic')
                if len(techniques) > 1
            ]
        }

def create_visualizations(analysis_results):
    """Create all visualizations for the dashboard"""
    visuals = {}
    
    # Severity Distribution
    severity_data = pd.DataFrame(
        list(analysis_results['summary']['severity_distribution'].items()),
        columns=['Severity', 'Count']
    )
    visuals['severity_pie'] = px.pie(
        severity_data,
        values='Count',
        names='Severity',
        title="Incident Severity Distribution"
    )
    
    # Technique Timeline
    dates = list(analysis_results['temporal_analysis']['technique_evolution'].keys())
    first_date = dates[0]
    techniques = list(analysis_results['temporal_analysis']['technique_evolution'][first_date].keys())
    
    technique_timeline = go.Figure()
    for technique in techniques:
        values = [
            analysis_results['temporal_analysis']['technique_evolution'][date][technique]
            for date in dates
        ]
        technique_timeline.add_trace(go.Scatter(
            x=dates,
            y=values,
            name=str(technique),
            mode='lines+markers'
        ))
    technique_timeline.update_layout(
        title='Technique Usage Over Time',
        xaxis_title='Date',
        yaxis_title='Number of Incidents',
        height=500
    )
    visuals['technique_timeline'] = technique_timeline
    
    return visuals

def main():
    st.set_page_config(page_title="ATT&CK Analysis Dashboard", page_icon="🛡️", layout="wide")
    
    st.title("🛡️ ATT&CK Analysis Dashboard")
    st.markdown("""
    This dashboard analyzes security incidents using the MITRE ATT&CK framework.
    Upload your incident data CSV file to begin analysis.
    """)
    
    uploaded_file = st.file_uploader("Upload CSV File", type="csv")
    
    if uploaded_file:
        try:
            # Read and analyze data
            df = pd.read_csv(uploaded_file)
            analyzer = AttackAnalyzer()
            analysis_results, error = analyzer.analyze_csv(df)
            
            if error:
                st.error(f"Analysis error: {error}")
                return
            
            # Create visualizations
            visuals = create_visualizations(analysis_results)
            
            # Display Dashboard
            tab1, tab2, tab3, tab4 = st.tabs([
                "📊 Overview",
                "🎯 Techniques",
                "📈 Timeline",
                "⚠️ Risk Analysis"
            ])
            
            with tab1:
                # Summary metrics
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Incidents", analysis_results['summary']['total_incidents'])
                with col2:
                    st.metric("Unique Techniques", analysis_results['summary']['unique_techniques'])
                with col3:
                    st.metric("Unique Tactics", analysis_results['summary']['unique_tactics'])
                
                # Severity distribution
                st.plotly_chart(visuals['severity_pie'])
                
                # Time period
                st.info(f"Analysis Period: {analysis_results['summary']['time_period']['start']} to {analysis_results['summary']['time_period']['end']}")
            
            with tab2:
                st.subheader("Technique Analysis")
                for technique in analysis_results['technique_analysis']:
                    with st.expander(f"{technique['technique_id']} - {technique['name']}"):
                        cols = st.columns([2, 1])
                        with cols[0]:
                            st.markdown(f"""
                            **Description:**
                            {technique['description']}
                            
                            **Detection Guidance:**
                            {technique['detection']}
                            
                            **Mitigation Steps:**
                            {technique['mitigation']}
                            """)
                        with cols[1]:
                            st.markdown(f"""
                            **Statistics:**
                            - Total Incidents: {technique['count']}
                            - Associated Tactics: {', '.join(technique['associated_tactics'])}
                            - Platforms Affected: {', '.join(technique['platforms'])}
                            
                            **Severity Breakdown:**
                            ```json
                            {json.dumps(technique['severity_breakdown'], indent=2)}
                            ```
                            """)
            
            with tab3:
                st.subheader("Temporal Analysis")
                st.plotly_chart(visuals['technique_timeline'])
                
                # Daily incidents
                st.subheader("Daily Incident Counts")
                daily_data = pd.DataFrame(
                    list(analysis_results['temporal_analysis']['daily_counts'].items()),
                    columns=['Date', 'Incidents']
                )
                st.line_chart(daily_data.set_index('Date'))
            
            with tab4:
                st.subheader("Risk Analysis")
                
                # High severity techniques
                st.markdown("### High-Severity Techniques")
                high_sev = pd.DataFrame(
                    list(analysis_results['risk_analysis']['high_severity_techniques'].items()),
                    columns=['Technique', 'Count']
                ).sort_values('Count', ascending=False)
                st.bar_chart(high_sev.set_index('Technique'))
                
                # Critical combinations
                st.markdown("### Critical Technique Combinations")
                for combo in analysis_results['risk_analysis']['critical_combinations']:
                    st.warning(f"""
                    **Tactic:** {combo['tactic']}
                    **Techniques Involved:** {', '.join(combo['techniques'])}
                    **Total Incidents:** {combo['incident_count']}
                    """)
        
        except Exception as e:
            st.error("Error processing data")
            st.exception(e)

if __name__ == "__main__":
    main()