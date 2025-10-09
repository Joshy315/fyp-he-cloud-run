# Stage 1: Build Stage (Includes C/C++ compilers for 'python-seal')
FROM python:3.11-slim as builder

# Install system dependencies needed for compilation (CRITICAL)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Stage 2: Final Run Stage (Lightweight and stable)
FROM python:3.11-slim

WORKDIR /app

# Copy the compiled dependencies from the builder stage
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages

# Copy the application code
COPY . .

# Set the Gunicorn command to run your Flask app ('app' instance in 'app.py')
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 app:app
