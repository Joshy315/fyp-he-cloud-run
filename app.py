import os
from flask import Flask, request, jsonify
import seal
from seal import *
import base64
import time
import numpy as np
import zlib  # ✅ Added for compression

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # ✅ Increased to 32 MB

def deserialize_from_base64(encoded_string, target_class, context=None, filename="temp_server_object"):
    """Deserialize SEAL objects from base64-encoded strings using file I/O"""
    # ✅ Decompress first
    compressed_data = base64.b64decode(encoded_string)
    bytes_data = zlib.decompress(compressed_data)
    
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

def serialize_to_base64(seal_object, filename="temp_server_result"):
    """Serialize SEAL objects to base64-encoded strings with compression"""
    seal_object.save(filename)
    with open(filename, 'rb') as f:
        bytes_data = f.read()
    os.remove(filename)
    
    # ✅ Compress before encoding
    compressed_data = zlib.compress(bytes_data, level=9)
    return base64.b64encode(compressed_data).decode('utf-8')

@app.route('/compute_average', methods=['POST'])
def compute_average():
    """
    Compute average of encrypted CKKS data with compression support
    """
    data = request.json
    
    # Validate required fields
    required_fields = ['parms', 'cipher_data', 'galois_keys', 'relin_keys', 'sample_size']
    if not all(k in data for k in required_fields):
        return jsonify({'error': f'Missing required fields. Need: {required_fields}'}), 400
    
    try:
        print("📦 Deserializing compressed parameters...")
        
        # Deserialize with decompression
        parms = deserialize_from_base64(data['parms'], EncryptionParameters, filename="temp_s_parms")
        context = SEALContext(parms)
        
        if not context.parameters_set():
            return jsonify({'error': 'Invalid encryption parameters'}), 400
        
        ckks_encoder = CKKSEncoder(context)
        evaluator = Evaluator(context)
        slot_count = ckks_encoder.slot_count()
        
        print(f"✅ Context created. Slot count: {slot_count}")
        
        # Load encrypted data and keys
        print("🔑 Loading encrypted data and keys...")
        cloud_cipher = deserialize_from_base64(data['cipher_data'], Ciphertext, context, "temp_s_cipher")
        cloud_galois_keys = deserialize_from_base64(data['galois_keys'], GaloisKeys, context, "temp_s_galois")
        cloud_relin_keys = deserialize_from_base64(data['relin_keys'], RelinKeys, context, "temp_s_relin")
        
        sample_size = int(data['sample_size'])
        print(f"✅ Loaded. Computing average of {sample_size} values...")
        
        start_time = time.time()
        
        # =====================================================================
        # COMPUTE SUM USING ROTATIONS OF ORIGINAL CIPHERTEXT
        # =====================================================================
        sum_cipher = Ciphertext(cloud_cipher)
        
        print(f"   Computing sum with {sample_size-1} rotations...")
        for i in range(1, sample_size):
            rotated = evaluator.rotate_vector(cloud_cipher, i, cloud_galois_keys)
            evaluator.add_inplace(sum_cipher, rotated)
        
        print(f"✅ Sum computed in slot 0")
        
        # =====================================================================
        # DIVIDE BY SAMPLE_SIZE TO GET AVERAGE
        # =====================================================================
        division_value = 1.0 / sample_size
        division_vector = np.full(slot_count, division_value, dtype=np.float64)

        # Encode divisor with scale 1.0 to avoid scale growth
        division_plain = ckks_encoder.encode(division_vector, 1.0)
        
        print(f"   Dividing by {sample_size} (using scale=1.0)")
        
        avg_cipher = evaluator.multiply_plain(sum_cipher, division_plain)
        
        print("   Relinearizing result...")
        evaluator.relinearize_inplace(avg_cipher, cloud_relin_keys)
        
        print("   Division complete.")
        
        processing_time = (time.time() - start_time) * 1000
        print(f"✅ Average computed in {processing_time:.2f} ms")
        
        # =====================================================================
        # SERIALIZE AND RETURN WITH COMPRESSION
        # =====================================================================
        encoded_result = serialize_to_base64(avg_cipher, "temp_s_result")
        
        print(f"📦 Result size (compressed): {len(encoded_result) / 1024:.1f} KB")
        
        return jsonify({
            'encrypted_result': encoded_result,
            'cloud_processing_time_ms': processing_time
        })
        
    except zlib.error as e:
        print(f"❌ Decompression error: {str(e)}")
        return jsonify({
            'error': 'Decompression failed. Client may not have sent compressed data.',
            'type': 'DecompressionError'
        }), 400
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'error': str(e),
            'type': type(e).__name__
        }), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for Cloud Run"""
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
    print(f"✅ Compression enabled (zlib)")
    app.run(debug=False, host='0.0.0.0', port=port)
