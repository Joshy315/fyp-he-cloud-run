# Use an official Python runtime as a parent image
FROM python:3.11-slim-bookworm

# Set the working directory in the container
WORKDIR /app

# Install system dependencies required for building SEAL from source
# build-essential for C/C++ compilers, cmake for SEAL
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        git && \
    rm -rf /var/lib/apt/lists/*

# Copy the requirements.txt file into the container
COPY requirements.txt .

# Install Python dependencies, including SEAL (which will now build from source)
# --no-cache-dir to save space
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application code into the container
COPY . .

# Expose the port that the app runs on
EXPOSE 8080

# Define the command to run your app using gunicorn as specified in Procfile
# (Cloud Run usually ignores Procfile if Dockerfile is present, so we specify here)
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 app:app
