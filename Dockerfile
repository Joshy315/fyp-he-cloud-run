# --- STAGE 1: BUILDER ---
# This stage installs all necessary C/C++ compilation tools and installs Python packages.
FROM python:3.11-slim as builder

# 1. Install system dependencies required for compilation (build-essential, cmake, python3-dev)
# The update and install are combined to ensure a clean layer and up-to-date packages.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    python3-dev && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# 2. Install Python dependencies with --user to compile them into a non-system directory
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# --- STAGE 2: FINAL IMAGE ---
# This stage uses a clean, small image and only includes the compiled dependencies and code.
FROM python:3.11-slim

# 1. Copy the application source code
WORKDIR /app
COPY . .

# 2. Copy the compiled Python packages from the builder stage
# This includes the compiled 'python-seal' extension.
COPY --from=builder /root/.local /usr/local/

# 3. Cloud Run configuration
# Set the environment variable for the PATH to include the copied user binaries
ENV PATH="/root/.local/bin:${PATH}"

# Cloud Run defaults to port 8080
ENV PORT 8080

# Run the application (assuming your main entry file is app.py)
CMD ["python", "app.py"]
