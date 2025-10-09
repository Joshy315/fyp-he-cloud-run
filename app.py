
import os
from flask import Flask, request, jsonify
import seal
from seal import *
from io import BytesIO
import base64
import time

app = Flask(__name__)

# This function must now also use files to load the data
def deserialize_from_base64(encoded_string, target_class, context=None, filename="temp_server_object"):
    bytes_data = base64.b64decode(encoded_string)
    with open(filename, 'wb') as f:
        f.write(bytes_data)
    
    new_object = target_class()
    # EncryptionParameters.load() is special and doesn't need a context
    if target_class == EncryptionParameters:
        new_object.load(filename)
    else:
        new_object.load(context, filename)
    
    os.remove(filename) # Clean up
    return new_object

@app.route('/compute_average', methods=['POST'])
def compute_average():
    data = request.json
    try:
        # 1. Recreate SEAL Context
        # We give each deserialization a unique temp filename to avoid conflicts
        parms = deserialize_from_base64(data['parms'], EncryptionParameters, filename="temp_s_parms")
        context = SEALContext(parms)
        ckks_encoder = CKKSEncoder(context)
        evaluator = Evaluator(context)
        
        # 2. Deserialize all required data from client
        cloud_cipher = deserialize_from_base64(data['cipher_data'], Ciphertext, context, "temp_s_cipher")
        cloud_galois_keys = deserialize_from_base64(data['galois_keys'], GaloisKeys, context, "temp_s_galois")
        cloud_relin_keys = deserialize_from_base64(data['relin_keys'], RelinKeys, context, "temp_s_relin")
        sample_size = int(data['sample_size'])
        
        start_time = time.time()
        
        # --- HEAVY COMPUTATION ---
        # Sum all elements in the encrypted vector
        rotated_ciphers = [evaluator.rotate_vector(cloud_cipher, i, cloud_galois_keys) for i in range(sample_size)]
        total_sum_cipher = evaluator.add_many(rotated_ciphers)
        
        # Divide to get the average
        scale = total_sum_cipher.scale()
        division_plain = ckks_encoder.encode(1.0 / sample_size, scale)
        avg_cipher = evaluator.multiply_plain(total_sum_cipher, division_plain)
        
        # Relinearize after multiplication
        evaluator.relinearize_inplace(avg_cipher, cloud_relin_keys)
        evaluator.rescale_to_next_inplace(avg_cipher)
        
        processing_time = (time.time() - start_time) * 1000

        # 3. Serialize and return result
        result_filename = "temp_s_result"
        avg_cipher.save(result_filename)
        with open(result_filename, 'rb') as f:
            bytes_data = f.read()
        os.remove(result_filename)
        encoded_result = base64.b64encode(bytes_data).decode('utf-8')

        return jsonify({
            'encrypted_result': encoded_result,
            'cloud_processing_time_ms': processing_time
        })
    except Exception as e:
        # Provide a more detailed error message for debugging
        return jsonify({'error': str(e), 'traceback': repr(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
