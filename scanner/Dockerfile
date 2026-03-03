FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Pas het commando hieronder aan per container (bv. server starten of script runnen)
CMD ["python", "main.py"]