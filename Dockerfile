FROM python:3.12-slim

WORKDIR /app

# The service needs only these; predict.py evaluates the models in plain Python (no LightGBM).
RUN pip install --no-cache-dir "fastapi>=0.115" "uvicorn>=0.30" "requests>=2.31"

COPY course_schema.py features.py predict.py main.py ./
COPY models/ models/

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
