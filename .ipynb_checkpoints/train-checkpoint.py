import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, LSTM, Dense, Dropout
from tensorflow.keras.callbacks import EarlyStopping
import pickle
import json

class AttackPredictor:
    def __init__(self, max_words=10000, max_len=200):
        self.max_words = max_words
        self.max_len = max_len
        self.tokenizer = Tokenizer(num_words=max_words)
        self.technique_encoder = LabelEncoder()
        self.tactic_encoder = LabelEncoder()
        self.model = None
        
    def preprocess_data(self, df):
        """Preprocess the text data and encode labels"""
        # Tokenize descriptions
        self.tokenizer.fit_on_texts(df['description'])
        X = self.tokenizer.texts_to_sequences(df['description'])
        X = pad_sequences(X, maxlen=self.max_len)
        
        # Process techniques (take first technique for each report)
        techniques = df['techniques_used'].apply(lambda x: eval(x)[0] if isinstance(x, str) else x[0])
        y_techniques = self.technique_encoder.fit_transform(techniques)
        
        # Process tactics (take first tactic for each report)
        tactics = df['tactics_observed'].apply(lambda x: eval(x)[0] if isinstance(x, str) else x[0])
        y_tactics = self.tactic_encoder.fit_transform(tactics)
        
        return X, y_techniques, y_tactics
    
    def build_model(self, vocab_size, n_techniques, n_tactics):
        """Build and compile the LSTM model"""
        model = Sequential([
            Embedding(vocab_size, 100, input_length=self.max_len),
            LSTM(128, return_sequences=True),
            Dropout(0.3),
            LSTM(64),
            Dropout(0.3),
            Dense(64, activation='relu'),
            Dropout(0.3),
            Dense(n_techniques, activation='softmax')  # Only predict techniques for now
        ])
        
        model.compile(optimizer='adam',
                     loss='sparse_categorical_crossentropy',
                     metrics=['accuracy'])
        
        self.model = model
        return model
    
    def train(self, X, y_techniques, y_tactics, epochs=10, batch_size=32):
        """Train the model"""
        # Only use techniques for now to simplify the problem
        X_train, X_val, y_train, y_val = train_test_split(X, y_techniques, 
                                                         test_size=0.2, 
                                                         random_state=42)
        
        # Train the model
        early_stopping = EarlyStopping(monitor='val_loss', 
                                     patience=3, 
                                     restore_best_weights=True)
        
        history = self.model.fit(X_train, y_train,
                               validation_data=(X_val, y_val),
                               epochs=epochs,
                               batch_size=batch_size,
                               callbacks=[early_stopping])
        
        return history
    
    def save_model(self, model_path='attack_model.h5', 
                  tokenizer_path='tokenizer.pkl',
                  encoders_path='encoders.pkl'):
        """Save the model and preprocessing objects"""
        self.model.save(model_path)
        
        with open(tokenizer_path, 'wb') as f:
            pickle.dump(self.tokenizer, f)
            
        encoders = {
            'technique_encoder': self.technique_encoder,
            'tactic_encoder': self.tactic_encoder
        }
        with open(encoders_path, 'wb') as f:
            pickle.dump(encoders, f)

def main():
    # Load the dataset
    print("Loading dataset...")
    df = pd.read_csv('threat_reports.csv')
    
    # Initialize and train the model
    print("Initializing predictor...")
    predictor = AttackPredictor()
    
    # Preprocess data
    print("Preprocessing data...")
    X, y_techniques, y_tactics = predictor.preprocess_data(df)
    
    # Build model
    print("Building model...")
    vocab_size = len(predictor.tokenizer.word_index) + 1
    n_techniques = len(predictor.technique_encoder.classes_)
    n_tactics = len(predictor.tactic_encoder.classes_)
    predictor.build_model(vocab_size, n_techniques, n_tactics)
    
    # Train model
    print("Training model...")
    history = predictor.train(X, y_techniques, y_tactics)
    
    # Save model and preprocessing objects
    print("Saving model...")
    predictor.save_model()
    
    print("Training completed and model saved successfully!")

if __name__ == "__main__":
    main()