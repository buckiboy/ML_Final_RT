<H1>Real-Time Threat Detection and PrivateGPT Integration</H1>

This is a Flask-based web application for real-time threat detection and action recommendation using PrivateGPT. The application classifies events as threats or non-threats and provides recommended actions based on a learned playbook.

<b>Features</b>
<pre>
Real-Time Threat Detection: Classify network events as threats or non-threats.
PrivateGPT Integration: Get action recommendations from PrivateGPT for detected threats.
User Authentication: User registration, login, and logout functionality.
Data Management: Upload data, add new data, edit existing data, and retrain the model.
Logging: View logs of predictions and API requests.
Visualization: Display feature importances and confusion matrices.
</pre>
<b>Directory Structure</b>
<code>
ML_Final/
├── app4.py
├── prediction_service.py
├── templates/
│ ├── base.html
│ ├── index.html
│ ├── logs.html
│ ├── api_logs.html
│ ├── prediction_form.html
│ ├── upload.html
│ ├── trained_data.html
│ ├── retrain.html
│ ├── removed_data.html
│ ├── add_data.html
│ ├── edit_signature.html
│ ├── edit_label.html
│ ├── feature_importances.html
│ ├── show_confusion_matrix.html
│ └── debug_data.html
├── static/
│ ├── css/
│ │ └── styles.css
│ ├── js/
│ │ └── scripts.js
│ └── images/
│ └── threat_pie_chart.png
├── uploads/
│ └── example.csv
├── app.log
├── prediction_service.log
├── rf_model.pkl
├── trained_data.csv
├── real_time_data.csv
└── requirements.txt
</code>

<b>Installation</b>

Clone the repository:
<code>
git clone https://github.com/buckiboy/ML_Final_RT.git
cd app4.py
</code>

Create a virtual environment and activate it:
<code>
python3 -m venv venv
source venv/bin/activate # On Windows use venv\Scripts\activate
</code>

Install the required packages:
<code>
pip install -r requirements.txt
</code>

Prepare the initial data:

Place your initial network_traffic.csv in the project root.
Ensure trained_data.csv is available for training if no initial data is provided.
Running the Application

Start the prediction service:
<code>
python prediction_service.py
</code>

Start the main application:
<code>
python main_app.py
</code>

Access the application:

Open your browser and navigate to http://localhost:5000 for the main app.
Access http://localhost:5001/api_logs to view API request logs.
API Usage

To test the connection to the PrivateGPT API using curl:
<code>
curl -X POST http://192.168.1.12:8001/v1/chat/completions
-H "Content-Type: application/json"
-d '{
"messages": [{
"content": "src_ip: 126.210.100.33, dst_ip: 79.24.10.160, src_port: 56542, dst_port: 25753, protocol: UDP, signature: sig3, prediction: 1.0, prediction_proba: 0.53"
}],
"use_context": true,
"context_filter": null,
"include_sources": false,
"stream": false
}'
</code>

Template Files
<pre>
base.html: Base template with common layout (header, footer, etc.).
index.html: Template for the home page.
logs.html: Template to display the logs.
api_logs.html: Template to display API request logs.
prediction_form.html: Template for the prediction form.
upload.html: Template for uploading files.
trained_data.html: Template to display trained data.
retrain.html: Template for retraining the model.
removed_data.html: Template to display removed data.
add_data.html: Template for adding new data.
edit_signature.html: Template for editing signatures.
edit_label.html: Template for editing labels.
feature_importances.html: Template to display feature importances.
show_confusion_matrix.html: Template to display the confusion matrix.
debug_data.html: Template to display debug data.
trained_data.csv : Header used -  src_ip, dst_ip, src_port, dst_port, protocol, signature, label
real_time_data.csv: Header - src_ip, dst_ip, src_port, dst_port, protocol, signature, timestamp
</pre>

Contributing
<pre>
Fork the repository.
Create your feature branch (git checkout -b feature/your-feature).
Commit your changes (git commit -m 'Add your feature').
Push to the branch (git push origin feature/your-feature).
Open a pull request.

</pre>
License

This project is licensed under the MIT License - see the LICENSE file for details.

