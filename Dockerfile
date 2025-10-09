# Stage 1: Build Stage (Includes compilation tools)
# Start with a full Python image that includes necessary build tools (like apt/dpkg)
FROM python:3.11-slim as builder

# 1. Install system-level dependencies for C/C++ compilation (Critical Step)
# This installs tools like gcc, g++, and cmake, which SEAL needs.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git && \
    rm -rf /var/lib/apt/lists/*

# 2. Copy dependencies and install Python packages
WORKDIR /app
COPY requirements.txt .

# Install Python dependencies, including 'seal', which will now compile successfully.
# The log suggests you are using a custom index for seal (https://github.com/Huelse/SEAL-Python/releases/)
# Make sure your requirements.txt or pip command includes that link if necessary.
RUN pip install --no-cache-dir -r requirements.txt

# Stage 2: Final Run Stage (Lightweight and secure)
# Switch to a smaller, cleaner image for running the final application
FROM python:3.11-slim

# Copy the compiled Python environment and application code from the builder stage
WORKDIR /app
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY . .

# Cloud Run expects the app to listen on the port defined by this environment variable
ENV PORT 8080

# Command to run your application (adjust 'main.py' to your actual startup file)
CMD ["python", "main.py"]
