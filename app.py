import os
from flask import Flask, request, jsonify
import seal
from seal import *
from io import BytesIO
import base64
import time

app = Flask(__name__)
# Set the maximum request size to 16 MB
app.config['MAX_CONTENT_LENGTH'] = 16 * 1000 * 1000

# This function must use files to load the data
def deserialize_from_base64(encoded_string, target_class, context=None, filename="temp_server_object"):
    bytes_data = base64.b64decode(encoded_string)
    with open(filename, 'wb') as f:
        f.write(bytes_data)
    
    if target_class == EncryptionParameters:
        # Special handling: Construct with scheme_type first, then load
        new_object = EncryptionParameters(scheme_type.ckks)
        new_object.load(filename)
    else:
        new_object = target_class()
        new_object.load(context, filename)
    
    os.remove(filename)
    return new_object

@app.route('/compute_average', methods=['POST'])
def compute_average():
    data = request.json
    try:
        parms = deserialize_from_base64(data['parms'], EncryptionParameters, filename="temp_s_parms")
        context = SEALContext(parms)
        ckks_encoder = CKKSEncoder(context)
        evaluator = Evaluator(context)
        
        cloud_cipher = deserialize_from_base64(data['cipher_data'], Ciphertext, context, "temp_s_cipher")
        cloud_galois_keys = deserialize_from_base64(data['galois_keys'], GaloisKeys, context, "temp_s_galois")
        cloud_relin_keys = deserialize_from_base64(data['relin_keys'], RelinKeys, context, "temp_s_relin")
        sample_size = int(data['sample_size'])
        
        start_time = time.time()
        
        rotated_ciphers = [evaluator.rotate_vector(cloud_cipher, i, cloud_galois_keys) for i in range(sample_size)]
        total_sum_cipher = evaluator.add_many(rotated_ciphers)
        
        scale = total_sum_cipher.scale()
        division_plain = ckks_encoder.encode(1.0 / sample_size, scale)
        avg_cipher = evaluator.multiply_plain(total_sum_cipher, division_plain)
        
        evaluator.relinearize_inplace(avg_cipher, cloud_relin_keys)
        evaluator.rescale_to_next_inplace(avg_cipher)
        
        processing_time = (time.time() - start_time) * 1000

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
        return jsonify({'error': str(e), 'traceback': repr(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
