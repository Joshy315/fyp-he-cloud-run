import os
from flask import Flask, request, jsonify
import seal
from seal import *
import base64
import time
import numpy as np
import zlib
from google.cloud import storage
import json

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024

# ✅ GCS Client (initialize once)
storage_client = storage.Client()

# --- HELPER FUNCTIONS ---
def deserialize_from_base64(encoded_string, target_class, context=None, filename="temp_server_object", is_compressed=True):
    """Deserialize SEAL objects from base64-encoded strings using file I/O"""
    decoded_data = base64.b64decode(encoded_string)
    
    if is_compressed:
        bytes_data = zlib.decompress(decoded_data)
    else:
        bytes_data = decoded_data
        
    with open(filename, 'wb') as f:
        f.write(bytes_data)
    if target_class == EncryptionParameters:
        new_object = EncryptionParameters(scheme_type.ckks)
        new_object.load(filename)
    else:
        new_object = target_class()
        new_object.load(context, filename)
    os.remove(filename)
    return new_object

def download_payload_from_gcs(gcs_uri, destination_file_name="/tmp/payload.json"):
    """Downloads the large payload file from GCS."""
    try:
        print(f"📥 Downloading payload from {gcs_uri}...")
        bucket_name = gcs_uri.split('/')[2]
        blob_name = '/'.join(gcs_uri.split('/')[3:])
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(blob_name)
        blob.download_to_filename(destination_file_name)
        print(f"✅ Payload downloaded to {destination_file_name}")
        return destination_file_name
    except Exception as e:
        print(f"❌ GCS Download Failed: {e}")
        raise

def upload_result_to_gcs(bucket_name, source_file_name, destination_blob_name):
    """Uploads the result file to GCS."""
    try:
        print(f"📤 Uploading result to gs://{bucket_name}/{destination_blob_name}...")
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(destination_blob_name)
        blob.upload_from_filename(source_file_name, content_type='application/octet-stream')
        print(f"✅ Result uploaded.")
        return f"gs://{bucket_name}/{destination_blob_name}"
    except Exception as e:
        print(f"❌ GCS Upload Failed: {e}")
        raise

# ✅ Endpoint for GCS workflow
@app.route('/compute_average_gcs', methods=['POST'])
def compute_average_gcs():
    """Handles HE computation - supports average and sum operations"""
    small_request_data = request.json
    gcs_payload_path = small_request_data.get('gcs_payload_path')
    sample_size = small_request_data.get('sample_size', 0)
    operation = small_request_data.get('operation', 'average')  # 'average' or 'sum'

    if not gcs_payload_path:
        return jsonify({'error': 'Missing gcs_payload_path in request'}), 400

    try:
        # STEP 1-3: Download and deserialize (same as before)
        local_payload_file = download_payload_from_gcs(gcs_payload_path)
        
        print("📦 Loading payload from downloaded file...")
        with open(local_payload_file, 'r') as f:
            payload = json.load(f)
        os.remove(local_payload_file)
        
        print("📦 Deserializing parameters from payload...")
        parms = deserialize_from_base64(payload['parms'], EncryptionParameters, 
                                       filename="temp_s_parms", is_compressed=False)
        context = SEALContext(parms)
        if not context.parameters_set():
            return jsonify({'error': 'Invalid params'}), 400
        
        ckks_encoder = CKKSEncoder(context)
        evaluator = Evaluator(context)
        slot_count = ckks_encoder.slot_count()
        print(f"✅ Context created. Slot count: {slot_count}")

        print("🔑 Loading encrypted data and keys...")
        cloud_cipher = deserialize_from_base64(payload['cipher_data'], Ciphertext, 
                                              context, "temp_s_cipher", is_compressed=True)
        cloud_galois_keys = deserialize_from_base64(payload['galois_keys'], GaloisKeys, 
                                                    context, "temp_s_galois", is_compressed=True)
        cloud_relin_keys = deserialize_from_base64(payload['relin_keys'], RelinKeys, 
                                                   context, "temp_s_relin", is_compressed=True)
        print(f"✅ Loaded. Operation: {operation}, Sample size: {sample_size}")

        # STEP 4: Perform HE Computation
        start_time = time.time()
        
        # --- Summation (Binary Tree) ---
        sum_cipher = Ciphertext(cloud_cipher)
        rotation_steps = []
        power = 1
        while power < sample_size:
            rotation_steps.append(power)
            power *= 2
        print(f"   Using binary tree rotation steps: {rotation_steps}")
        for step in rotation_steps:
            rotated = evaluator.rotate_vector(sum_cipher, step, cloud_galois_keys)
            evaluator.add_inplace(sum_cipher, rotated)
        print(f"✅ Sum computed")
        
        if operation == "average":
            # --- Division for Average ---
            division_value = 1.0 / sample_size
            division_vector = np.full(slot_count, division_value, dtype=np.float64)
            division_plain = ckks_encoder.encode(division_vector, sum_cipher.scale())
            print(f"   Dividing by {sample_size}")
            result_cipher = evaluator.multiply_plain(sum_cipher, division_plain)
            print("   Rescaling...")
            evaluator.rescale_to_next_inplace(result_cipher)
            print("   Average complete")
        else:  # operation == "sum"
            result_cipher = sum_cipher
            print("   Sum complete (no division)")
        
        processing_time = (time.time() - start_time) * 1000
        print(f"✅ {operation.capitalize()} computed in {processing_time:.2f} ms")

        # STEP 5-6: Serialize and return (same as before)
        print("📦 Serializing result...")
        temp_seal_file = "/tmp/result_seal.bin"
        result_cipher.save(temp_seal_file)
        
        with open(temp_seal_file, 'rb') as f:
            seal_bytes = f.read()
        os.remove(temp_seal_file)
        
        compressed_data = zlib.compress(seal_bytes, level=9)
        result_b64 = base64.b64encode(compressed_data).decode('utf-8')
        
        print(f"✅ Result serialized ({len(compressed_data)} bytes compressed)")

        return jsonify({
            'status': 'complete',
            'result_data': result_b64,
            'cloud_processing_time_ms': processing_time,
            'operation': operation
        })

    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e), 'type': type(e).__name__}), 500

# --- Health check endpoint ---
@app.route('/health', methods=['GET'])
def health_check():
    try:
        from seal import EncryptionParameters, scheme_type
        return jsonify({
            'status': 'healthy',
            'seal_available': True,
            'compression_enabled': True
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8080))
    print(f"🚀 Starting server on port {port}...")
    print(f"✅ GCS Integration Enabled")
    app.run(debug=False, host='0.0.0.0', port=port)
