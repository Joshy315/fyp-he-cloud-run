import os
from flask import Flask, request, jsonify
import seal
from seal import *
import base64
import time
import numpy as np
import zlib

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32 MB

# No global cache - we'll receive everything per request

def deserialize_from_base64(encoded_string, target_class, context=None, filename="temp_server_object"):
    """Deserialize compressed SEAL objects"""
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
    """Serialize SEAL objects with compression"""
    seal_object.save(filename)
    with open(filename, 'rb') as f:
        bytes_data = f.read()
    os.remove(filename)
    
    compressed_data = zlib.compress(bytes_data, level=9)
    return base64.b64encode(compressed_data).decode('utf-8')

@app.route('/setup_keys', methods=['POST'])
def setup_keys():
    """Upload and cache keys (one-time)"""
    data = request.json
    
    required_fields = ['parms', 'galois_keys', 'relin_keys']
    if not all(k in data for k in required_fields):
        return jsonify({'error': f'Missing: {required_fields}'}), 400
    
    try:
        print("🔑 Setting up keys...")
        print(f"   parms: {len(data['parms']) / 1024:.1f} KB")
        print(f"   galois_keys: {len(data['galois_keys']) / 1024:.1f} KB")
        print(f"   relin_keys: {len(data['relin_keys']) / 1024:.1f} KB")
        
        parms = deserialize_from_base64(data['parms'], EncryptionParameters, filename="temp_setup_parms")
        context = SEALContext(parms)
        
        if not context.parameters_set():
            return jsonify({'error': 'Invalid parameters'}), 400
        
        # ✅ Verify 4096 configuration (accept any valid 4096 config)
        poly_degree = parms.poly_modulus_degree()
        coeff_mod = parms.coeff_modulus()
        prime_bits = [mod.bit_count() for mod in coeff_mod]
        
        print(f"   Poly degree: {poly_degree}")
        print(f"   Prime bits: {prime_bits}")
        
        if poly_degree != 4096:
            return jsonify({'error': f'Expected 4096, got {poly_degree}', 'type': 'ConfigMismatch'}), 400
        
        galois_keys = deserialize_from_base64(data['galois_keys'], GaloisKeys, context, "temp_setup_galois")
        relin_keys = deserialize_from_base64(data['relin_keys'], RelinKeys, context, "temp_setup_relin")
        
        encoder = CKKSEncoder(context)
        evaluator = Evaluator(context)
        slot_count = encoder.slot_count()
        
        # Cache
        GLOBAL_CACHE['context'] = context
        GLOBAL_CACHE['galois_keys'] = galois_keys
        GLOBAL_CACHE['relin_keys'] = relin_keys
        GLOBAL_CACHE['encoder'] = encoder
        GLOBAL_CACHE['evaluator'] = evaluator
        GLOBAL_CACHE['slot_count'] = slot_count
        
        print(f"✅ Keys cached (Slots: {slot_count})")
        
        return jsonify({
            'status': 'success',
            'slot_count': slot_count,
            'poly_modulus_degree': poly_degree
        })
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e), 'type': type(e).__name__}), 500

@app.route('/compute_average', methods=['POST'])
def compute_average():
    """Compute average on encrypted data"""
    data = request.json
    
    required_fields = ['cipher_data', 'sample_size']
    if not all(k in data for k in required_fields):
        return jsonify({'error': f'Missing: {required_fields}'}), 400
    
    if GLOBAL_CACHE['context'] is None:
        return jsonify({'error': 'Call /setup_keys first', 'type': 'KeyNotFoundError'}), 400
    
    try:
        print("📦 Computing with cached keys...")
        
        context = GLOBAL_CACHE['context']
        galois_keys = GLOBAL_CACHE['galois_keys']
        relin_keys = GLOBAL_CACHE['relin_keys']
        encoder = GLOBAL_CACHE['encoder']
        evaluator = GLOBAL_CACHE['evaluator']
        slot_count = GLOBAL_CACHE['slot_count']
        
        print(f"   cipher_data: {len(data['cipher_data']) / 1024:.1f} KB")
        
        cloud_cipher = deserialize_from_base64(data['cipher_data'], Ciphertext, context, "temp_s_cipher")
        sample_size = int(data['sample_size'])
        
        print(f"✅ Computing average of {sample_size} values...")
        start_time = time.time()
        
        # =====================================================================
        # ROTATION-SUM (no level consumption)
        # =====================================================================
        sum_cipher = Ciphertext(cloud_cipher)
        
        rotation_steps = []
        power = 1
        while power < sample_size:
            rotation_steps.append(power)
            power *= 2
        
        print(f"   Rotations: {rotation_steps}")
        
        for step in rotation_steps:
            rotated = evaluator.rotate_vector(sum_cipher, step, galois_keys)
            evaluator.add_inplace(sum_cipher, rotated)
        
        print(f"✅ Sum computed")
        
        # Check levels
        context_data = context.get_context_data(sum_cipher.parms_id())
        chain_index = context_data.chain_index()
        current_scale = sum_cipher.scale()
        
        print(f"   Chain index: {chain_index}, Scale: {current_scale:.2e}")
        
        if chain_index == 0:
            return jsonify({'error': 'Not enough levels', 'type': 'LevelError'}), 400
        
        # =====================================================================
        # DIVISION (consumes 1 level)
        # =====================================================================
        division_value = 1.0 / sample_size
        division_vector = np.full(slot_count, division_value, dtype=np.float64)
        division_plain = encoder.encode(division_vector, current_scale)
        
        avg_cipher = evaluator.multiply_plain(sum_cipher, division_plain)
        
        # Relinearize and rescale
        evaluator.relinearize_inplace(avg_cipher, relin_keys)
        evaluator.rescale_to_next_inplace(avg_cipher)
        
        processing_time = (time.time() - start_time) * 1000
        print(f"✅ Average computed in {processing_time:.2f} ms")
        
        # Serialize result
        encoded_result = serialize_to_base64(avg_cipher, "temp_s_result")
        print(f"📦 Result: {len(encoded_result) / 1024:.1f} KB")
        
        return jsonify({
            'encrypted_result': encoded_result,
            'cloud_processing_time_ms': processing_time
        })
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e), 'type': type(e).__name__}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check"""
    try:
        from seal import EncryptionParameters, scheme_type
        return jsonify({
            'status': 'healthy',
            'seal_available': True,
            'keys_cached': GLOBAL_CACHE['context'] is not None
        }), 200
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8080))
    print(f"🚀 Starting server on port {port}...")
    print(f"✅ 4096 configuration with key caching")
    app.run(debug=False, host='0.0.0.0', port=port)
