import os
from flask import Flask, request, jsonify
import seal
from seal import *
import base64
import time
import numpy as np
import zlib

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024

def deserialize_from_base64(encoded_string, target_class, context=None, filename="temp_server_object"):
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
    seal_object.save(filename)
    with open(filename, 'rb') as f:
        bytes_data = f.read()
    os.remove(filename)
    
    compressed_data = zlib.compress(bytes_data, level=9)
    return base64.b64encode(compressed_data).decode('utf-8')

@app.route('/compute_average', methods=['POST'])
def compute_average():
    data = request.json
    
    required_fields = ['parms', 'cipher_data', 'galois_keys', 'relin_keys', 'sample_size']
    if not all(k in data for k in required_fields):
        return jsonify({'error': f'Missing: {required_fields}'}), 400
    
    try:
        print("📦 Deserializing...")
        
        parms = deserialize_from_base64(data['parms'], EncryptionParameters, filename="temp_s_parms")
        context = SEALContext(parms)
        
        if not context.parameters_set():
            return jsonify({'error': 'Invalid parameters'}), 400
        
        encoder = CKKSEncoder(context)
        evaluator = Evaluator(context)
        slot_count = encoder.slot_count()
        
        print(f"✅ Context: {parms.poly_modulus_degree()} poly, {slot_count} slots")
        
        cloud_cipher = deserialize_from_base64(data['cipher_data'], Ciphertext, context, "temp_s_cipher")
        galois_keys = deserialize_from_base64(data['galois_keys'], GaloisKeys, context, "temp_s_galois")
        relin_keys = deserialize_from_base64(data['relin_keys'], RelinKeys, context, "temp_s_relin")
        
        sample_size = int(data['sample_size'])
        print(f"✅ Computing average of {sample_size} values")
        
        start_time = time.time()
        
        # Rotation-sum
        sum_cipher = Ciphertext(cloud_cipher)
        rotation_steps = []
        power = 1
        while power < sample_size:
            rotation_steps.append(power)
            power *= 2
        
        for step in rotation_steps:
            rotated = evaluator.rotate_vector(sum_cipher, step, galois_keys)
            evaluator.add_inplace(sum_cipher, rotated)
        
        print(f"✅ Sum computed")
        
        # Check levels
        context_data = context.get_context_data(sum_cipher.parms_id())
        chain_index = context_data.chain_index()
        current_scale = sum_cipher.scale()
        
        if chain_index == 0:
            return jsonify({'error': 'Not enough levels', 'type': 'LevelError'}), 400
        
        # Division
        division_value = 1.0 / sample_size
        division_vector = np.full(slot_count, division_value, dtype=np.float64)
        division_plain = encoder.encode(division_vector, current_scale)
        
        avg_cipher = evaluator.multiply_plain(sum_cipher, division_plain)
        evaluator.relinearize_inplace(avg_cipher, relin_keys)
        evaluator.rescale_to_next_inplace(avg_cipher)
        
        processing_time = (time.time() - start_time) * 1000
        print(f"✅ Done in {processing_time:.2f} ms")
        
        encoded_result = serialize_to_base64(avg_cipher, "temp_s_result")
        
        return jsonify({
            'encrypted_result': encoded_result,
            'cloud_processing_time_ms': processing_time
        })
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e), 'type': type(e).__name__}), 500

@app.route('/health', methods=['GET'])
def health_check():
    try:
        from seal import EncryptionParameters, scheme_type
        return jsonify({'status': 'healthy', 'seal_available': True}), 200
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8080))
    print(f"🚀 Server starting on port {port}")
    app.run(debug=False, host='0.0.0.0', port=port)
