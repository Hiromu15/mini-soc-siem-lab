FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY detector_api ./detector_api

EXPOSE 8000
CMD ["uvicorn", "detector_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
