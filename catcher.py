from flask import Flask, request, jsonify, render_template_string, send_from_directory
import sqlite3
import time
import os
import json
import hashlib
import mimetypes

# ToDo: Write code to handle more than one file/post data:
# curl.exe -F "image2=@C:\test.bat"  -F "filecomment=This is an image file"  -F "image=@C:\malware\putty.exe" localhost:5000/curltest.php

# ToDo: Handle 'sqlite3.OperationalError: database is locked' exception


app = Flask(__name__)

DB_FILE = "data.db"
STATIC_DIR = "static"
UPLOADS_DIR = "uploads"

def is_text_file(file_path):
    """Check if a file is a text-based file using MIME type detection."""
    mime_type, _ = mimetypes.guess_type(file_path)
    return mime_type and mime_type.startswith("text")

def is_image_file(file_path):
    """Check if a file is an image file using MIME type detection."""
    mime_type, _ = mimetypes.guess_type(file_path)
    return mime_type and mime_type.startswith("image")

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    method TEXT,
                    headers TEXT,
                    params TEXT,
                    body TEXT,
                    mime_type TEXT,
                    file_name TEXT,
                    original_file_name TEXT,
                    file_content TEXT,
                    path TEXT,
                    raw_post_data TEXT
                 )''')
    conn.commit()
    conn.close()


init_db()

def hash_file(file_stream):
    """Compute SHA-256 hash of the uploaded file."""
    hasher = hashlib.sha256()
    while chunk := file_stream.read(8192):
        hasher.update(chunk)
    file_stream.seek(0)  # Reset file pointer after reading
    return hasher.hexdigest()

# Serve static files (jQuery, DataTables, CSS)
@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory(STATIC_DIR, filename)

@app.route('/uploads/<path:filename>')
def serve_uploads(filename):
    return send_from_directory(UPLOADS_DIR, filename)

@app.route('/uploadfile', methods=['GET', 'POST'])
def basic_upload():
    return '''
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>
    <form method=post enctype=multipart/form-data action='/anywhere'>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    '''

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>',methods=['GET', 'POST'])
def capture_request(path):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    method = request.method
    headers = json.dumps(dict(request.headers))  
    params = json.dumps(request.args.to_dict(flat=True))
    
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    full_path = request.path
    raw_post_data = None

    file_name = None
    original_file_name = None
    file_content = None  # Store text-based file content
    mime_type = None
    body = ""

    if request.method == 'POST':
        # Handle file uploads
        if request.files:
            if 'file' in request.files:
                file = request.files['file']
                original_file_name = file.filename
                file_hash = hash_file(file)
                file_ext = os.path.splitext(original_file_name)[1]
                file_name = f"{UPLOADS_DIR}/{file_hash}{file_ext}"

                if not os.path.exists(file_name):
                    file.save(file_name)
                mime_type, _ = mimetypes.guess_type(file_name)

                # Check if file is text-based and read content
                if is_text_file(file_name):
                    try:
                        with open(file_name, "r", encoding="utf-8", errors="ignore") as f:
                            file_content = f.read(500)  # Limit to 500 characters to prevent UI slowdown
                            body = file_content
                    except Exception as e:
                        body = f"[Error reading file: {str(e)}]"
                elif is_image_file(file_name):
                    body = "Image File"
                else:
                    body = "Binary file"
        else:
           
            #get raw post data
            raw_post_data = request.get_data(as_text=True)
            body = raw_post_data

    # Store in DB
    c.execute("INSERT INTO logs (timestamp, method, headers, params, body, file_name, mime_type, original_file_name, file_content, path, raw_post_data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
              (timestamp, method, headers, params, body, file_name, mime_type, original_file_name, file_content, full_path, raw_post_data))
    conn.commit()
    conn.close()

    return jsonify({"message": "Captured"}), 200

@app.route('/logs', methods=['GET'])
def get_logs():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("SELECT * FROM logs ORDER BY id DESC")
    logs = c.fetchall()
    conn.close()

    formatted_logs = []
    for log in logs:
        formatted_logs.append({
            "id": log[0],
            "timestamp": log[1],
            "method": log[2],
            "headers": json.loads(log[3]),
            "params": json.loads(log[4]),
            "body": log[5],
            "mime_type": log[6],
            "file_name": log[7],
            "original_file_name": log[8],
            "file_content": log[9],
            "path": log[10],
            "raw_post_data": log[11]
        })

    return jsonify(formatted_logs)


@app.route('/view', methods=['GET'])
def view_logs():
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Captured Logs</title>
        <script src="/static/jquery.min.js"></script>
        <script src="/static/datatables.min.js"></script>
        <link rel="stylesheet" href="/static/datatables.min.css">
    </head>
    <body>
        <h2>Captured Logs</h2>
        <table id="logsTable" class="display">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Time</th>
                    <th>Method</th>
                    <th>Path</th>
                    <th>Headers</th>
                    <th>Params</th>
                    <th>Body</th>
                    <th>Original Filename</th>
                    <th>Mime Type</th>
                    <th>File</th>
                    <th>Raw POST Data</th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>

        <script>
    $(document).ready(function() {
        $.getJSON("/logs", function(data) {
            var table = $('#logsTable').DataTable();
            data.forEach(row => {
                let paramStr = Object.entries(row.params).map(([key, value]) => `${key}: ${value}`).join("<br>");
                let headerStr = Object.entries(row.headers).map(([key, value]) => `${key}: ${value}`).join("<br>");
                let bodyStr = "<pre>" + row.body + "</pre>";
                let original_file_name = "N/A";

                let fileDisplay = "N/A";
                if (row.file_content) {
                    let formattedFileContent = row.file_content.replace(/\\r\\n|\\n|\\r/g, "<br>");
                    fileDisplay = `<pre>${formattedFileContent}</pre>`; // Display text file content
                } else if (row.file_name) {
                                   
                    if (row.mime_type.startsWith('image/')) {
                        fileDisplay = `<img src="${row.file_name}" alt="${row.original_file_name}" style="max-width: 200px; max-height: 200px;">`;
                    } else {
                        fileDisplay = `<a href="${row.file_name}" target="_blank"> ${row.original_file_name} </a>`; // Show download link for binary files
                    }
                }

                let raw_post_display = row.raw_post_data ? `<pre>${row.raw_post_data}</pre>` : 'N/A';

                table.row.add([
                    row.id,
                    row.timestamp,
                    row.method,
                    row.path,
                    headerStr,
                    paramStr,
                    bodyStr,
                    row.original_file_name || "N/A",
                    row.mime_type || "N/A",
                    fileDisplay,
                    raw_post_display
                ]).draw();
            });
        });
    });
    </script>

    </body>
    </html>
    ''')

if __name__ == "__main__":
    os.makedirs(UPLOADS_DIR, exist_ok=True)
    os.makedirs(STATIC_DIR, exist_ok=True)

    # Ensure static files exist (if not already downloaded)
    if not os.path.exists(f"{STATIC_DIR}/jquery.min.js"):
        import urllib.request
        print("Downloading jQuery and DataTables...")
        urllib.request.urlretrieve("https://code.jquery.com/jquery-3.7.1.min.js", f"{STATIC_DIR}/jquery.min.js")
        urllib.request.urlretrieve("https://cdn.datatables.net/2.2.2/js/dataTables.min.js", f"{STATIC_DIR}/datatables.min.js")
        urllib.request.urlretrieve("https://cdn.datatables.net/2.2.2/css/dataTables.dataTables.min.css", f"{STATIC_DIR}/datatables.min.css")
        print("Static files saved to /static.")

    app.run(debug=True, port=5000)
