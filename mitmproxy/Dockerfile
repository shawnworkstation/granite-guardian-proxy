FROM python:3.11.7-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir --upgrade pip
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Copy the middleware logic
COPY addon.py .

EXPOSE 8080
# Run as a non-root user
RUN useradd -m mitmuser && chown -R mitmuser /app
USER mitmuser

CMD ["mitmdump", "--listen-port", "8080", "--ssl-insecure", "-s", "addon.py"]