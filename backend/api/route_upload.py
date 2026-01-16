"""File Upload and Management Routes"""

import os
import json
from typing import Dict, Any
from werkzeug.utils import secure_filename
from flask import Blueprint, request, jsonify, current_app
from datetime import datetime

upload_bp = Blueprint('upload', __name__)

ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}

def allowed_file(filename: str) -> bool:
    """Check if file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@upload_bp.route('/upload', methods=['POST'])
def upload_pcap():
    """
    Upload a PCAP file for analysis.
    
    Returns:
        {
            "success": bool,
            "file_id": str,
            "filename": str,
            "size": int,
            "uploaded_at": str,
            "message": str
        }
    """
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'success': False, 'error': 'Only .pcap and .pcapng files allowed'}), 400
    
    try:
        upload_dir = current_app.config.get('UPLOAD_DIR', 'data/uploads')
        os.makedirs(upload_dir, exist_ok=True)
        
        filename = secure_filename(file.filename)
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S_')
        saved_filename = timestamp + filename
        filepath = os.path.join(upload_dir, saved_filename)
        
        file.save(filepath)
        file_size = os.path.getsize(filepath)
        
        file_id = saved_filename.replace('.pcap', '').replace('.pcapng', '')
        
        return jsonify({
            'success': True,
            'file_id': file_id,
            'filename': saved_filename,
            'size': file_size,
            'uploaded_at': datetime.utcnow().isoformat(),
            'message': f'File uploaded successfully: {saved_filename}'
        }), 200
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@upload_bp.route('/files', methods=['GET'])
def list_files():
    """List all uploaded files."""
    try:
        upload_dir = current_app.config.get('UPLOAD_DIR', 'data/uploads')
        
        if not os.path.exists(upload_dir):
            return jsonify({'success': True, 'files': []}), 200
        
        files = []
        for filename in os.listdir(upload_dir):
            if filename.endswith(('.pcap', '.pcapng')):
                filepath = os.path.join(upload_dir, filename)
                size = os.path.getsize(filepath)
                mtime = os.path.getmtime(filepath)
                files.append({
                    'filename': filename,
                    'size': size,
                    'uploaded_at': datetime.fromtimestamp(mtime).isoformat(),
                })
        
        return jsonify({'success': True, 'files': files}), 200
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@upload_bp.route('/delete/<file_id>', methods=['DELETE'])
def delete_file(file_id: str):
    """Delete an uploaded file."""
    try:
        upload_dir = current_app.config.get('UPLOAD_DIR', 'data/uploads')
        
        # Find and delete the file
        for filename in os.listdir(upload_dir):
            if file_id in filename and filename.endswith(('.pcap', '.pcapng')):
                filepath = os.path.join(upload_dir, filename)
                os.remove(filepath)
                return jsonify({'success': True, 'message': 'File deleted'}), 200
        
        return jsonify({'success': False, 'error': 'File not found'}), 404
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
