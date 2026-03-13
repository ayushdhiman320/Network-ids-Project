import joblib
import pandas as pd

model = joblib.load("model/dos_detection_model.pkl")


def predict_attack(features):

    if features is None:
        return 0

    df = pd.DataFrame([features])

    try:
        prediction = model.predict(df)[0]
        return prediction
    except:
        return 0