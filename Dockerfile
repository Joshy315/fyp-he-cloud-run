# Stage 1: Build Stage (Includes compilation tools)
# Start with a full Python image that contains tools like apt/dpkg
FROM python:3.11-slim as builder

# 1. Install system-level dependencies for C/C++ compilation (CRITICAL)
# These tools are necessary to compile the 'seal' library from source.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git && \
    rm -rf /var/lib/apt/lists/*

# 2. Copy dependencies and install Python packages
WORKDIR /app
COPY requirements.txt .

# Install Python dependencies, including 'seal'. This step now has the required tools.
# The `pip` command will automatically use the links specified in your requirements.txt.
RUN pip install --no-cache-dir -r requirements.txt

# Copy your application code (app.py, etc.)
COPY . .

# Stage 2: Final Run Stage (Lightweight for deployment)
# Use a cleaner, smaller image for the final production container.
FROM python:3.11-slim

# Copy the compiled Python environment and application code from the builder stage
WORKDIR /app
# Copy installed dependencies (like the compiled SEAL library)
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
# Copy your application files (app.py, etc.)
COPY --from=builder /app .

# Cloud Run requires the application to listen on the $PORT environment variable
ENV PORT 8080

# Command to run your Flask/FastAPI server (Assuming your main file is 'app.py')
# If you are using Gunicorn, use this:
# CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 app:app
# If you are using a basic Flask server (less recommended for prod), use this:
CMD ["python", "app.py"]
