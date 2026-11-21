"""Competition service for the automated prediction rounds (template: riehlegroup/pcom-course-setup).

GET  /health   -> {"health": "up"}
POST /predict  {"testdata_download_endpoint": ..., "prediction_upload_endpoint": ...}
     downloads the input CSV (several rows = versions of one package), predicts for the latest
     version (the target window is 90 days after the latest version) with predict.py, and uploads
     a one-row CSV with the five target_ghsa_*_count_90d columns.

Run:  python main.py    (or: uvicorn main:app --host 0.0.0.0 --port 8000)
"""
import csv, io
import requests, uvicorn
from fastapi import BackgroundTasks, FastAPI
from pydantic import BaseModel
from course_schema import TARGET_COLUMNS
from predict import load_models, predict_row

app = FastAPI(title="PCOM prediction API")
MODELS = load_models()


class EvaluationBody(BaseModel):
    testdata_download_endpoint: str
    prediction_upload_endpoint: str


def predict_csv(text):
    """Input CSV text -> one-row output CSV text with the target columns (never empty, never NaN)."""
    rows = list(csv.DictReader(io.StringIO(text)))
    if rows:  # latest version by publication time; ties or missing dates -> the last row
        latest = max(enumerate(rows), key=lambda t: ((t[1].get("published_at") or "").strip(), t[0]))[1]
        pred = predict_row(latest, MODELS)
    else:
        pred = {c: 0.0 for c in TARGET_COLUMNS}
    out = io.StringIO()
    w = csv.DictWriter(out, fieldnames=TARGET_COLUMNS, lineterminator="\n")
    w.writeheader()
    w.writerow({c: round(pred[c], 4) for c in TARGET_COLUMNS})
    return out.getvalue()


def start_prediction(download_url, upload_url):
    try:
        r = requests.get(download_url, timeout=30)
        r.raise_for_status()
        result = predict_csv(r.content.decode("utf-8-sig"))
        up = requests.post(upload_url, files={"predictions": ("prediction.csv", result, "text/csv")}, timeout=30)
        up.raise_for_status()
        print("Evaluation Result:", up.text)
    except Exception as e:
        print("Error:", e)


@app.post("/predict", status_code=200)
async def prediction(payload: EvaluationBody, background_tasks: BackgroundTasks):
    background_tasks.add_task(start_prediction, payload.testdata_download_endpoint, payload.prediction_upload_endpoint)
    return {"status": "prediction started"}


@app.get("/health", status_code=200)
async def health():
    return {"health": "up"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
