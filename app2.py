import streamlit as st
import pandas as pd
import numpy as np
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
import pickle
import os

# Custom CSS for styling
st.markdown("""
    <style>
    .main {
        background-color: #F5F5F5;
    }
    .stButton>button {
        background-color: #4CAF50;
        color: white;
        border-radius: 5px;
    }
    .prediction-box {
        padding: 20px;
        border-radius: 10px;
        margin: 10px 0;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    .severity-high { background-color: #FFCCCB; }
    .severity-medium { background-color: #FFE4B5; }
    .severity-low { background-color: #90EE90; }
    </style>
    """, unsafe_allow_html=True)

@st.cache_resource
def load_components():
    """Load model and preprocessing components"""
    model = load_model('attack_model.h5')
    with open('tokenizer.pkl', 'rb') as f:
        tokenizer = pickle.load(f)
    with open('encoders.pkl', 'rb') as f:
        encoders = pickle.load(f)
    return model, tokenizer, encoders

def create_description(row):
    """Recreate the description from CSV row"""
    return (f"Incident {row['incident_id']} of {row['severity']} severity involved "
            f"primary tactic {row['primary_tactic']} using technique {row['technique_id']}. "
            f"Secondary tactics observed: {row['secondary_tactics']} "
            f"with techniques: {row['secondary_techniques']}")

def preprocess_input(df, tokenizer, max_len=250):
    """Preprocess the input data"""
    descriptions = df.apply(create_description, axis=1).str.lower()
    sequences = tokenizer.texts_to_sequences(descriptions)
    return pad_sequences(sequences, maxlen=max_len, padding='post', truncating='post')

def main():
    st.title("🛡️ Cyber Attack Predictor")
    st.markdown("Upload incident data CSV to predict attack techniques and tactics")

    # Sidebar for file upload and info
    with st.sidebar:
        st.header("⚙️ Configuration")
        uploaded_file = st.file_uploader("Upload CSV", type="csv")
        model, tokenizer, encoders = load_components()
        
        st.markdown("---")
        st.markdown("**Expected CSV Columns:**")
        st.write("- incident_id, severity, primary_tactic")
        st.write("- technique_id, secondary_tactics")
        st.write("- secondary_techniques")

    if uploaded_file:
        try:
            df = pd.read_csv(uploaded_file)
            required_columns = ['incident_id', 'severity', 'primary_tactic',
                               'technique_id', 'secondary_tactics', 'secondary_techniques']
            
            if not all(col in df.columns for col in required_columns):
                st.error("❌ Invalid CSV format. Missing required columns.")
                return

            # Preprocess data
            X = preprocess_input(df, tokenizer)
            
            # Make predictions
            predictions = model.predict(X)
            predicted_indices = np.argmax(predictions, axis=1)
            confidence = np.max(predictions, axis=1)
            predicted_techniques = encoders['technique_encoder'].inverse_transform(predicted_indices)
            
            # Display results
            st.subheader("🔍 Prediction Results")
            for idx, row in df.iterrows():
                with st.container():
                    # Severity color coding
                    severity_class = f"severity-{row['severity'].lower()}"
                    st.markdown(f"""
                        <div class="prediction-box {severity_class}">
                            <h4>Incident ID: {row['incident_id']}</h4>
                            <div style="display: flex; gap: 20px;">
                                <div style="flex: 1;">
                                    <p>📊 Severity: <strong>{row['severity']}</strong></p>
                                    <p>🔑 Primary Tactic: {row['primary_tactic']}</p>
                                </div>
                                <div style="flex: 1;">
                                    <p>🎯 Predicted Technique: <strong>{predicted_techniques[idx]}</strong></p>
                                    <p>✅ Confidence: {confidence[idx]:.1%}</p>
                                </div>
                            </div>
                            <progress value="{confidence[idx]}" max="1" style="width: 100%;"></progress>
                        </div>
                    """, unsafe_allow_html=True)

            # Show summary statistics
            st.markdown("---")
            st.subheader("📈 Prediction Summary")
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Incidents", len(df))
            with col2:
                st.metric("Most Common Technique", pd.Series(predicted_techniques).mode()[0])
            with col3:
                avg_confidence = np.mean(confidence)
                st.metric("Average Confidence", f"{avg_confidence:.1%}")

        except Exception as e:
            st.error(f"Error processing file: {str(e)}")

if __name__ == "__main__":
    main()