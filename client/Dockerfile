FROM python:3.11.7-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir --upgrade pip
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Copy source code last
COPY client.py .
# Run as a non-root user
RUN useradd -m appuser && chown -R appuser /app
USER appuser

CMD ["python3", "client.py"]