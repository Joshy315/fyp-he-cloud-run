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

# Clone, initialize submodule, and install SEAL-Python in one robust step
RUN git clone https://github.com/Huelse/SEAL-Python.git && \
    cd SEAL-Python && \
    git checkout v4.1.1-4 && \
    git submodule update --init --recursive && \
    pip install .

# Now, copy and install the other dependencies (Flask, gunicorn)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application code (app.py, etc.)
COPY . .

# Expose the port that the app runs on
EXPOSE 8080

# Define the command to run your app
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 app:app
