import sys
import os
from final_model.feature_extractor import PhishingFeatureExtractor  # Update the import path as needed
import certifi
ca = certifi.where()

from dotenv import load_dotenv
load_dotenv()
mongo_db_url = os.getenv("MONGODB_URL_KEY")
print(mongo_db_url)

import pymongo
from networksecurity.exception.exception import NetworkSecurityException
from networksecurity.logging.logger import logging
from networksecurity.pipeline.training_pipeline import TrainingPipeline

from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, File, UploadFile, Request, Form
from uvicorn import run as app_run
from fastapi.responses import Response, JSONResponse, HTMLResponse
from starlette.responses import RedirectResponse
import pandas as pd

from networksecurity.utils.main_util.util import load_object
from networksecurity.utils.ml_util.model.estimator import NetworkModel

# MongoDB setup (optional, remove if not needed)
client = pymongo.MongoClient(mongo_db_url, tlsCAFile=ca)
from networksecurity.constant.training_pipeline import DATA_INGESTION_COLLECTION_NAME, DATA_INGESTION_DATABASE_NAME
database = client[DATA_INGESTION_DATABASE_NAME]
collection = database[DATA_INGESTION_COLLECTION_NAME]

app = FastAPI()
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.templating import Jinja2Templates
templates = Jinja2Templates(directory="./templates")

# Initialize the feature extractor
feature_extractor = PhishingFeatureExtractor()

@app.get("/", tags=["authentication"])
async def index():
    return RedirectResponse(url="/docs")

@app.get("/train")
async def train_route():
    try:
        train_pipeline = TrainingPipeline()
        train_pipeline.run_pipeline()
        return Response("Training is successful")
    except Exception as e:
        raise NetworkSecurityException(e, sys)

@app.post("/predict-url")
async def predict_url(url: str = Form(...)):
    """Predict if a single URL is phishing (0) or safe (1)."""
    try:
        # Step 1: Extract features from the URL using PhishingFeatureExtractor
        features_list = feature_extractor.extract_features(url)
        
        # Convert the list of features to a dictionary with the correct feature names
        features_dict = {
            feature_name: feature_value 
            for feature_name, feature_value in zip(feature_extractor.feature_order, features_list)
        }
        
        # Step 2: Convert dict to DataFrame
        features_df = pd.DataFrame([features_dict])

        # Step 3: Load model and preprocessor
        preprocessor = load_object("final_model/preprocessor.pkl")
        model = load_object("final_model/model.pkl")

        # Step 4: Preprocess and predict
        transformed_features = preprocessor.transform(features_df)
        prediction = model.predict(transformed_features)[0]

        # Step 5: Return result
        result = "Phishing 🚨" if prediction == 0 else "Safe ✅"
        return JSONResponse({"url": url, "prediction": result})

    except Exception as e:
        raise NetworkSecurityException(e, sys)

@app.post("/predict-csv")
async def predict_csv(file: UploadFile = File(...)):
    """Batch prediction from CSV (0 = phishing, 1 = safe)."""
    try:
        df = pd.read_csv(file.file)
        preprocessor = load_object("final_model/preprocessor.pkl")
        model = load_object("final_model/model.pkl")
        network_model = NetworkModel(preprocessor=preprocessor, model=model)
        
        y_pred = network_model.predict(df)
        df['prediction'] = ["Phishing 🚨" if x == 0 else "Safe ✅" for x in y_pred]
        
        # Save and return results
        df.to_csv('prediction_output/output.csv', index=False)
        return JSONResponse({"message": "Predictions saved to output.csv"})
    
    except Exception as e:
        raise NetworkSecurityException(e, sys)

if __name__ == "__main__":
    app_run(app, host="0.0.0.0", port=8000)