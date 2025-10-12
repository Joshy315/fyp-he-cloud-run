# Use an official Python runtime as a parent image
FROM python:3.11-slim-bookworm

# Set the working directory in the container
WORKDIR /app

# Install system dependencies required for building SEAL from source
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        git && \
    rm -rf /var/lib/apt/lists/*

# Copy your application's requirements.txt
COPY requirements.txt .

# Install all Python dependencies in a single, unified step.
# This ensures everything is in the same, correct path.
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir "git+https://github.com/Huelse/SEAL-Python.git@v4.1.1-4#egg=seal"

# Copy the rest of your application code (app.py, etc.)
COPY . .

# Expose the port that the app runs on
EXPOSE 8080

# Define the command to run your app
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 app:app
