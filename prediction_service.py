from flask import Flask, request, jsonify, render_template, flash
import requests
import logging

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'anothersecretkey'

# Configure logging
logging.basicConfig(filename='prediction_service.log', level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

@app.route('/get_recommendations', methods=['POST'])
def get_recommendations():
    data = request.json
    logging.info(f'Received data for recommendation: {data}')
    
    prediction = data

    gpt_payload = {
        "messages": [{
            "content": (
                f"src_ip: {prediction['src_ip']}, "
                f"dst_ip: {prediction['dst_ip']}, "
                f"src_port: {prediction['src_port']}, "
                f"dst_port: {prediction['dst_port']}, "
                f"protocol: {prediction['protocol']}, "
                "provide recommended action or advice"
            )
        }],
        "use_context": True,
        "context_filter": None,
        "include_sources": False,
        "stream": False
    }

    try:
        response = requests.post("http://192.168.1.12:8001/v1/chat/completions", json=gpt_payload)
        response.raise_for_status()
        gpt_recommendations = response.json()['choices'][0]['message']['content']
        logging.info(f'Received recommendations from LLM: {gpt_recommendations}')
    except requests.exceptions.RequestException as e:
        logging.error(f'Error retrieving recommendations: {e}')
        return jsonify({"error": str(e), "recommendations": "Could not retrieve recommendations due to an error."}), 500

    return jsonify({"recommendations": gpt_recommendations})


@app.route('/log_llm_request', methods=['POST'])
def log_llm_request():
    try:
        data = request.json
        logging.info(f'LLM request data: {data}')
        return jsonify({"status": "success"})
    except Exception as e:
        logging.error(f'Error logging LLM request: {e}')
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    logging.info('Starting prediction_service application...')
    app.run(host='0.0.0.0', port=5001, debug=True)
