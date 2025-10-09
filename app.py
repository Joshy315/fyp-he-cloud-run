# Corrected app.py
import os
from flask import Flask, request, jsonify
import seal
from seal import *
from io import BytesIO
import base64
import time

app = Flask(__name__)

def deserialize_from_base64(encoded_string, target_class, context=None):
    bytes_data = base64.b64decode(encoded_string)
    stream = BytesIO(bytes_data)
    new_object = target_class()
    if context:
        new_object.load(context, stream)
    else:
        new_object.load(stream) # For context-free objects like parms
    return new_object

@app.route('/compute_average', methods=['POST'])
def compute_average():
    data = request.json
    try:
        # 1. Recreate SEAL Context
        parms = deserialize_from_base64(data['parms'], EncryptionParameters)
        context = SEALContext(parms)
        ckks_encoder = CKKSEncoder(context)
        evaluator = Evaluator(context)
        
        # 2. Deserialize all required data from client
        cloud_cipher = deserialize_from_base64(data['cipher_data'], Ciphertext, context)
        cloud_galois_keys = deserialize_from_base64(data['galois_keys'], GaloisKeys, context)
        # CRITICAL FIX: Load the relin_keys sent from the client
        cloud_relin_keys = deserialize_from_base64(data['relin_keys'], RelinKeys, context)
        sample_size = int(data['sample_size'])
        
        start_time = time.time()
        
        # --- HEAVY COMPUTATION ---
        # Sum all elements in the encrypted vector
        total_sum_cipher = evaluator.add_many(
            [evaluator.rotate_vector(cloud_cipher, i, cloud_galois_keys) for i in range(sample_size)]
        )
        
        # Divide to get the average
        scale = total_sum_cipher.scale()
        division_plain = ckks_encoder.encode(1.0 / sample_size, scale)
        avg_cipher = evaluator.multiply_plain(total_sum_cipher, division_plain)
        
        # Relinearize after multiplication using the received keys
        evaluator.relinearize_inplace(avg_cipher, cloud_relin_keys)
        evaluator.rescale_to_next_inplace(avg_cipher)
        
        processing_time = (time.time() - start_time) * 1000

        # 3. Serialize and return result
        stream = BytesIO()
        avg_cipher.save(stream)
        encoded_result = base64.b64encode(stream.getvalue()).decode('utf-8')

        return jsonify({
            'encrypted_result': encoded_result,
            'cloud_processing_time_ms': processing_time
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
