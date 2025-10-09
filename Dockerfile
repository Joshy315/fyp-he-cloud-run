# --- STAGE 1: BUILDER ---
# This stage uses build tools to compile python-seal.
FROM python:3.11-slim as builder

# 1. CRITICAL: Install system dependencies for C++ compilation (build-essential, cmake, python3-dev)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    python3-dev && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# 2. Install Python dependencies
# We use --user to install compiled packages into a predictable user path.
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# --- STAGE 2: FINAL IMAGE (Runtime) ---
# This stage uses a clean, small image for the final deployment.
FROM python:3.11-slim

# 1. Copy the application source code
WORKDIR /app
COPY . .

# 2. Copy the compiled Python packages from the builder stage
# This copies the compiled 'python-seal' extension and other libraries.
COPY --from=builder /root/.local /usr/local/

# 3. Set PATH and Environment Variables
# Add the copied binaries to the PATH
ENV PATH="/root/.local/bin:${PATH}"
# Set the default Cloud Run port
ENV PORT 8080

# Run the application using the Flask development server (or Gunicorn if you added it to requirements.txt)
# Assuming your main entry file is app.py
CMD ["python", "app.py"]
