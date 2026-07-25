from flask import Blueprint, render_template, request, jsonify, send_file
from app.parser import analyze_logs
from app.pdf_report import generate_report
from datetime import datetime
import json

main = Blueprint('main', __name__)

@main.route('/')
def index():
    """Render the main dashboard."""
    return render_template('index.html')

@main.route('/analyze', methods=['POST'])
def analyze():
    """
    Accept uploaded log file, analyze it and return JSON results.
    Validates file presence, extension and content before processing.
    """
    if 'logfile' not in request.files:
        return jsonify({"error": "No file uploaded"})

    file = request.files['logfile']

    if file.filename == '':
        return jsonify({"error": "No file selected"})

    # Validate file extension
    allowed = {'log', 'txt'}
    ext = file.filename.rsplit('.', 1)[-1].lower()
    if ext not in allowed:
        return jsonify({"error": f"Invalid file type .{ext} — only .log and .txt files are supported"})

    try:
        content = file.read().decode('utf-8', errors='ignore')

        if not content.strip():
            return jsonify({"error": "File is empty"})

        if len(content.splitlines()) < 2:
            return jsonify({"error": "File too short — please upload a valid access log"})

        results = analyze_logs(content)
        return jsonify(results)

    except Exception as e:
        return jsonify({"error": f"Analysis failed: {str(e)}"})

@main.route('/export-pdf', methods=['POST'])
def export_pdf():
    """Generate and return a PDF report from analysis results."""
    try:
        data = json.loads(request.form.get('data', '{}'))
        buffer = generate_report(data)
        filename = f"log_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        return send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({"error": str(e)})
