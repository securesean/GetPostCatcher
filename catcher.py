from flask import Flask, request, jsonify, render_template_string, send_from_directory, Response
import sqlite3
import time
import os
import json
import hashlib
import mimetypes
from functools import wraps

# ToDo: Get image display to work againdis
# ToDo: Write code to handle more than one file/post data:
# curl.exe -F "image2=@C:\test.bat"  -F "filecomment=This is an image file"  -F "image=@C:\malware\putty.exe" localhost:5000/curltest.php
# curl.exe -d "name=curl" -d "tool=cmdline" http://localhost:5000/bin
# curl.exe --upload-file http://localhost:5000/filename
#  -T, --upload-file,  --data-binary, --data-urlencode and --data-raw
# https://curl.se/docs/manpage.html

# ToDo: Handle 'sqlite3.OperationalError: database is locked' exception
# ToDo: Support basic http auth


app = Flask(__name__)

DB_FILE = "data.db"
STATIC_DIR = "static"
UPLOADS_DIR = "uploads"


# --- Basic HTTP Auth ---
USERNAME = "user"
PASSWORD = "password"

def check_auth(username, password):
    """This function is called to check if a username /
    password combination is valid."""
    return username == USERNAME and password == PASSWORD

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
    'Access Denied', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated
# --- End Basic HTTP Auth ---

def is_text_file(file_path):
    """Check if a file is mostly readable english text"""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read(500)  # Read the first 500 characters
            # Check if the text contains mostly printable characters
            printable_ratio = sum(1 for char in text if char.isprintable()) / len(text) if text else 0
            return printable_ratio > 0.9  # Adjust threshold as needed
    except UnicodeDecodeError:
        return False
    except Exception:
        return False

    

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
                    path TEXT
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
@app.route('/<path:path>',methods=['GET', 'POST','PUT'])
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
    file_ext = None
    body = ""

    if request.method == 'POST' or request.method == 'PUT':
        #if 'file' in request.files:
        for fileString in request.files:
            raw_post_data = None
            file_name = None
            original_file_name = None
            file_content = None  # Store text-based file content
            mime_type = None
            file_ext = None
            body = ""
            file = request.files[fileString]
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
            c.execute("INSERT INTO logs (timestamp, method, headers, params, body, file_name, mime_type, original_file_name, file_content, path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (timestamp, method, headers, params, body, file_name, mime_type, original_file_name, file_content, full_path))
        # End file for loop

        for form in request.form:
            file_name = None
            original_file_name = None
            file_content = None  
            mime_type = None
            file_ext = None
            body = form + " = " + request.form[form]
            c.execute("INSERT INTO logs (timestamp, method, headers, params, body, file_name, mime_type, original_file_name, file_content, path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (timestamp, method, headers, params, body, file_name, mime_type, original_file_name, file_content, full_path))
        # End form for loop

        #get raw post data
        raw_post_data = request.get_data() # as_text=True
        if raw_post_data != '':
            file_name = None
            original_file_name = None
            file_content = None  
            mime_type = None
            body = None
            file_ext = ""

            
            # sha-256 this string raw_post_data, then save the file with the hash as the file name and original extention
            file_hash = hashlib.sha256(raw_post_data).hexdigest()
            file_ext = os.path.splitext(path)[1]
            original_file_name = (path.split('/')[-1]).replace('..', '')
            file_name = f"{UPLOADS_DIR}/{file_hash}{file_ext}"

            if not os.path.exists(file_name):
                open(file_name, "wb").write(raw_post_data)
            mime_type, _ = mimetypes.guess_type(file_name)
            # Based on mime_type, assign proper exention and rename the file

            # Check if file is text-based and read content
            if mime_type is None and is_text_file(file_name):
                try:
                    with open(file_name, "r", encoding="utf-8", errors="ignore") as f:
                        file_content = f.read(500)  # Limit to 500 characters to prevent UI slowdown
                        body = file_content
                except Exception as e:
                    body = f"[Error reading file: {str(e)}]"
            elif mime_type is None and is_image_file(file_name):
                body = "Image File"
            else:
                body = "Binary file"

            c.execute("INSERT INTO logs (timestamp, method, headers, params, body, file_name, mime_type, original_file_name, file_content, path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                        (timestamp, method, headers, params, body, file_name, mime_type, original_file_name, file_content, full_path))


    # Store in DB
    conn.commit()
    conn.close()

    return jsonify({"message": "Captured"}), 200

@app.route('/logs', methods=['GET'])
def get_logs():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("SELECT * FROM logs ORDER BY timestamp ASC")
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
            "path": log[10]
        })

    return jsonify(formatted_logs)


@app.route('/view', methods=['GET'])
@requires_auth
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
                    <th>URL Params</th>
                    <th>Body (partial)</th>
                    <th>Original Filename</th>
                    <th>Mime Type</th>
                    <th>File</th>
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
                let original_file_name = "";

                let fileDisplay = "";
                if (row.file_name) { 
                    if (row.mime_type.startsWith('image/')) {
                        fileDisplay = `<img src="${row.file_name}" alt="${row.original_file_name}" style="max-width: 200px; max-height: 200px;">`;
                    } else {
                        fileDisplay = `<a href="${row.file_name}" target="_blank"> ${row.original_file_name} </a>`; // Show download link for binary files
                    }
                }

                let raw_post_display = row.raw_post_data ? `<pre>${row.raw_post_data}</pre>` : '';

                table.row.add([
                    row.id,
                    row.timestamp,
                    row.method,
                    row.path,
                    headerStr,
                    paramStr,
                    bodyStr,
                    row.original_file_name || "",
                    row.mime_type || "",
                    fileDisplay
                    
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
