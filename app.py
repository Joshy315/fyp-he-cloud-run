# app.py - The Cloud Server
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
    # Context is needed for most SEAL objects
    if context:
        new_object.load(context, stream)
    else:
        new_object.load(stream)
    return new_object

@app.route('/compute_average', methods=['POST'])
def compute_average():
    data = request.json
    try:
        # 1. Recreate SEAL Context from parameters
        parms = EncryptionParameters()
        parms.load(BytesIO(base64.b64decode(data['parms'])))
        context = SEALContext(parms)

        # 2. Deserialize the encrypted data and keys
        cloud_cipher = deserialize_from_base64(data['cipher_data'], Ciphertext, context)
        cloud_galois_keys = deserialize_from_base64(data['galois_keys'], GaloisKeys, context)
        sample_size = int(data['sample_size'])

        # --- HEAVY COMPUTATION ---
        start_time = time.time()
        evaluator = Evaluator(context)
        ckks_encoder = CKKSEncoder(context)

        # Sum all elements in the encrypted vector
        total_sum_cipher = evaluator.add_many(
            [evaluator.rotate_vector(cloud_cipher, i, cloud_galois_keys) for i in range(sample_size)]
        )

        # Divide by the number of elements to get the average
        division_plain = ckks_encoder.encode(1.0 / sample_size, total_sum_cipher.scale())
        avg_cipher = evaluator.multiply_plain(total_sum_cipher, division_plain)
        evaluator.relinearize_inplace(avg_cipher, keygen.create_relin_keys()) # Needed after multiplication
        evaluator.rescale_to_next_inplace(avg_cipher)

        processing_time = (time.time() - start_time) * 1000

        # 3. Serialize result for sending back
        stream = BytesIO()
        avg_cipher.save(stream)
        encoded_result = base64.b64encode(stream.getvalue()).decode('utf-8')

        return jsonify({
            'encrypted_result': encoded_result,
            'cloud_processing_time_ms': processing_time
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
