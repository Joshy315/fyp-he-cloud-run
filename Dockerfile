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

# Install Python dependencies for building SEAL-Python
RUN pip install --no-cache-dir numpy pybind11

# Copy your application's requirements.txt
COPY requirements.txt .

# Install application Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Clone and build SEAL-Python from source (use main for stability)
RUN git clone --branch main https://github.com/Huelse/SEAL-Python.git seal-python && \
    cd seal-python && \
    git submodule update --init --recursive && \
    cd SEAL && \
    cmake -S . -B build \
        -DSEAL_USE_MSGSL=OFF \
        -DSEAL_USE_ZLIB=OFF \
        -DSEAL_USE_ZSTD=OFF \
        -DBUILD_SHARED_LIBS=ON && \
    cmake --build build --parallel && \
    cd .. && \
    # Copy the shared SEAL library to system path
    cp SEAL/build/lib/libseal*.so /usr/local/lib/ && \
    ldconfig && \
    # Build and install the Python bindings
    python setup.py build_ext --inplace && \
    python setup.py install && \
    # Test import during build to catch issues early
    python -c "import seal; print('SEAL imported successfully during build')" && \
    cd .. && \
    rm -rf seal-python  # Clean up to reduce image size

# Set LD_LIBRARY_PATH for runtime (safety net)
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# Copy the rest of your application code (app.py, etc.)
COPY . .

# Expose the port that the app runs on
EXPOSE 8080

# Define the command to run your app
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 app:app
