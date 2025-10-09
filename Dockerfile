# Use Python base image
FROM python:3.10-slim

# Install system dependencies (for building SEAL)
RUN apt-get update && apt-get install -y cmake g++ wget git

# Copy source code
WORKDIR /app
COPY . .

# Build and install Microsoft SEAL and SEAL-Python
RUN git clone https://github.com/microsoft/SEAL.git && \
    cd SEAL && cmake -S . -B build && cmake --build build && cmake --install build && \
    cd .. && git clone https://github.com/Huelse/SEAL-Python.git && \
    cd SEAL-Python && pip install .


# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose Cloud Run port
ENV PORT=8080
EXPOSE 8080

# Start server
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 app:app
