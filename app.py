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
    """
    Handles HE computation request where payload is in GCS.
    """
    small_request_data = request.json
    gcs_payload_path = small_request_data.get('gcs_payload_path')
    sample_size = small_request_data.get('sample_size', 0)

    if not gcs_payload_path:
        return jsonify({'error': 'Missing gcs_payload_path in request'}), 400

    try:
        # STEP 1: Download the large payload file from GCS
        local_payload_file = download_payload_from_gcs(gcs_payload_path)

        # STEP 2: Load the payload content from the downloaded file
        print("📦 Loading payload from downloaded file...")
        with open(local_payload_file, 'r') as f:
            payload = json.load(f)
        os.remove(local_payload_file)
        print("✅ Payload loaded.")

        # STEP 3: Deserialize parameters and keys
        print("📦 Deserializing parameters from payload...")
        parms = deserialize_from_base64(payload['parms'], EncryptionParameters, filename="temp_s_parms", is_compressed=False)
        context = SEALContext(parms)
        if not context.parameters_set():
            return jsonify({'error': 'Invalid params'}), 400
        
        print(f"🔍 Server context info:")
        print(f"   Poly modulus degree: {parms.poly_modulus_degree()}")
        print(f"   Coeff modulus sizes: {[mod.bit_count() for mod in parms.coeff_modulus()]}")
        
        ckks_encoder = CKKSEncoder(context)
        evaluator = Evaluator(context)
        slot_count = ckks_encoder.slot_count()
        print(f"✅ Context created. Slot count: {slot_count}")

        print("🔑 Loading encrypted data and keys from payload...")
        cloud_cipher = deserialize_from_base64(payload['cipher_data'], Ciphertext, context, "temp_s_cipher", is_compressed=True)
        cloud_galois_keys = deserialize_from_base64(payload['galois_keys'], GaloisKeys, context, "temp_s_galois", is_compressed=True)
        cloud_relin_keys = deserialize_from_base64(payload['relin_keys'], RelinKeys, context, "temp_s_relin", is_compressed=True)
        print(f"✅ Loaded. Computing average of {sample_size} values...")

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
        
        # --- Division (Match Scale + Rescale) ---
        division_value = 1.0 / sample_size
        division_vector = np.full(slot_count, division_value, dtype=np.float64)
        division_plain = ckks_encoder.encode(division_vector, sum_cipher.scale())
        print(f"   Dividing by {sample_size} (encoded at CT scale)")
        avg_cipher = evaluator.multiply_plain(sum_cipher, division_plain)
        print("   Rescaling result...")
        evaluator.rescale_to_next_inplace(avg_cipher)
        print("   Division complete.")
        
        # Calculate processing time
        processing_time = (time.time() - start_time) * 1000
        print(f"✅ Average computed in {processing_time:.2f} ms")

        # STEP 5: Serialize result using the SAME context
        print("📦 Serializing result with context...")
        
        # Use context.save() to get a complete context snapshot
        context_file = "/tmp/server_context.bin"
        
        # Save result ciphertext
        temp_seal_file = "/tmp/result_seal.bin"
        avg_cipher.save(temp_seal_file)
        
        with open(temp_seal_file, 'rb') as f:
            seal_bytes = f.read()
        os.remove(temp_seal_file)
        
        print(f"   Result size: {len(seal_bytes)} bytes")
        
        # Compress and encode
        compressed_data = zlib.compress(seal_bytes, level=9)
        result_b64 = base64.b64encode(compressed_data).decode('utf-8')
        
        print(f"   Compressed: {len(compressed_data)} bytes")
        print(f"   Base64: {len(result_b64)} chars")
        print(f"✅ Result serialized")

        # STEP 6: Return result - client will use its OWN parms to create matching context
        total_size = len(result_b64)
        
        if total_size < 30_000_000:  # 30MB limit
            print(f"   Returning result directly")
            return jsonify({
                'status': 'complete',
                'result_data': result_b64,
                'cloud_processing_time_ms': processing_time,
                'result_size_bytes': len(seal_bytes),
                'compressed_size_bytes': len(compressed_data),
                'use_client_context': True  # Signal client to use its own context
            })
        else:
            print(f"   Uploading to GCS...")
            local_result_file = "/tmp/result.enc"
            with open(local_result_file, 'wb') as f:
                f.write(compressed_data)
            
            bucket_name = gcs_payload_path.split('/')[2]
            result_blob_name = f"he_results/{os.path.basename(gcs_payload_path).replace('_payload.json', '_result.enc')}"
            result_gcs_path = upload_result_to_gcs(bucket_name, local_result_file, result_blob_name)
            os.remove(local_result_file)
            
            return jsonify({
                'status': 'complete',
                'result_gcs_path': result_gcs_path,
                'cloud_processing_time_ms': processing_time,
                'result_size_bytes': len(seal_bytes),
                'compressed_size_bytes': len(compressed_data),
                'use_client_context': True
            })

    except Exception as e:
        print(f"❌ Error processing GCS request: {str(e)}")
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
