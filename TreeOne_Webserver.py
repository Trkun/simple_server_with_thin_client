#!/usr/bin/env python3
import socket
import select
import sys
import os
import re
import uuid
import json
import time
import threading

# Configuration
HOST = '0.0.0.0'
WEB_PORT = 8298
FILES_DIR = "./files"
METADATA_FILE = "metadata.json"
BUFFER_SIZE = 4096
MAX_CACHEABLE_FILE_SIZE = 1024 * 1024  # 1 MB

# Global storage for sessions, download stats, and cache.
sessions = {}         # session_id -> username
download_stats = {}   # filename -> {"downloads": int, "total_time": float}
cache = {}            # endpoint key -> {"data": response, "timestamp": time.time()}

# Load file metadata from Assignment 1.
if os.path.exists(METADATA_FILE):
    with open(METADATA_FILE, "r") as f:
        data = f.read().strip()
        if data == "":
            metadata = {}
        else:
            try:
                metadata = json.loads(data)
            except Exception:
                metadata = {}
else:
    metadata = {}

def persist_metadata():
    with open(METADATA_FILE, "w") as f:
        json.dump(metadata, f)

def get_actual_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except:
        ip = "127.0.0.1"
    s.close()
    return ip

def get_cached_response(key):
    if key in cache and time.time() - cache[key]["timestamp"] < 60:
        print(f"[Cache] Using cached data for {key} at {time.strftime('%H:%M:%S')}")
        return cache[key]["data"]
    return None

def set_cached_response(key, data):
    cache[key] = {"data": data, "timestamp": time.time()}

def flush_cache(keys):
    for key in keys:
        cache.pop(key, None)

def send_http_response(conn, status, body, content_type="text/html", extra_headers=None):
    if extra_headers is None:
        extra_headers = {}
    if isinstance(body, bytes):
        content_length = len(body)
        response = f"HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {content_length}\r\n"
    else:
        body = body.encode("utf-8")
        content_length = len(body)
        response = f"HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {content_length}\r\n"
    for k, v in extra_headers.items():
        response += f"{k}: {v}\r\n"
    response += "\r\n"
    conn.sendall(response.encode("utf-8") + body)

def serve_static_file(conn, path):
    if path == "/":
        path = "/index.html"
    file_path = "." + path
    if not os.path.exists(file_path):
        send_http_response(conn, "404 Not Found", "404 Not Found")
        return
    with open(file_path, "rb") as f:
        content = f.read()
    if file_path.endswith(".js"):
        ctype = "application/javascript"
    elif file_path.endswith(".css"):
        ctype = "text/css"
    elif file_path.endswith(".png"):
        ctype = "image/png"
    elif file_path.endswith(".jpg") or file_path.endswith(".jpeg"):
        ctype = "image/jpeg"
    else:
        ctype = "text/html"
    send_http_response(conn, "200 OK", content, content_type=ctype)

def parse_cookies(cookie_str):
    cookies = {}
    for cookie in cookie_str.split(";"):
        if "=" in cookie:
            k, v = cookie.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies

def handle_api_request(conn, method, path, headers, body):
    cookies = parse_cookies(headers.get("Cookie", ""))
    session = cookies.get("session")
    username = sessions.get(session)

    if path.startswith("/api/login"):
        if method == "POST":
            uname = body.strip() or "Guest"
            new_session = str(uuid.uuid4())
            sessions[new_session] = uname
            extra = {"Set-Cookie": f"session={new_session}; HttpOnly"}
            send_http_response(conn, "200 OK", f"Logged in as {uname}", extra_headers=extra)
            return
        elif method == "DELETE":
            sessions.pop(session, None)
            send_http_response(conn, "200 OK", "Logged out")
            return
        elif method == "GET":
            if username:
                send_http_response(conn, "200 OK", f"Logged in as {username}")
            else:
                send_http_response(conn, "401 Unauthorized", "Not logged in")
            return

    if not username:
        send_http_response(conn, "401 Unauthorized", "Not logged in")
        return

    if path.startswith("/api/list"):
        cached = get_cached_response("/api/list")
        if cached:
            send_http_response(conn, "200 OK", cached, content_type="application/json")
            return
        file_list = [{"filename": fname, "owner": meta["owner"],
                      "size_mb": meta["size_mb"], "timestamp": meta["timestamp"]}
                     for fname, meta in metadata.items()]
        response_data = json.dumps(file_list)
        set_cached_response("/api/list", response_data)
        send_http_response(conn, "200 OK", response_data, content_type="application/json")
        return

    elif path.startswith("/api/stats"):
        cached = get_cached_response("/api/stats")
        if cached:
            send_http_response(conn, "200 OK", cached, content_type="application/json")
            return
        stats = {}
        total_downloads = total_time = 0
        for fname, stat in download_stats.items():
            downloads = stat["downloads"]
            avg_time = stat["total_time"] / downloads if downloads else 0
            stats[fname] = {"downloads": downloads, "avg_time": avg_time}
            total_downloads += downloads
            total_time += stat["total_time"]
        stats["overall"] = {"downloads": total_downloads,
                            "avg_time": (total_time / total_downloads) if total_downloads else 0}
        response_data = json.dumps(stats)
        set_cached_response("/api/stats", response_data)
        send_http_response(conn, "200 OK", response_data, content_type="application/json")
        return

    elif path.startswith("/api/get"):
        m = re.search(r"file=([^&]+)", path)
        if not m:
            send_http_response(conn, "400 Bad Request", "Missing file parameter")
            return
        fname = m.group(1)
        fpath = os.path.join(FILES_DIR, fname)
        if not os.path.exists(fpath):
            send_http_response(conn, "404 Not Found", "File not found")
            return
        filesize = os.path.getsize(fpath)
        cache_key = f"/api/get?file={fname}"
        use_cache = (filesize <= MAX_CACHEABLE_FILE_SIZE)
        if use_cache:
            cached = get_cached_response(cache_key)
            if cached:
                print(f"[Cache] Using cached data for {cache_key}")
                conn.sendall(cached)
                return
        with open(fpath, "rb") as f:
            file_data = f.read()
        extra = {"Content-Disposition": f"attachment; filename={fname}"}
        start_time = time.time()
        send_http_response(conn, "200 OK", file_data,
                           content_type="application/octet-stream", extra_headers=extra)
        elapsed = time.time() - start_time
        download_stats.setdefault(fname, {"downloads": 0, "total_time": 0.0})
        download_stats[fname]["downloads"] += 1
        download_stats[fname]["total_time"] += elapsed
        flush_cache(["/api/stats"])
        if use_cache:
            response = f"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
            response += f"Content-Disposition: attachment; filename={fname}\r\n"
            response += f"Content-Length: {len(file_data)}\r\n\r\n"
            full_response = response.encode("utf-8") + file_data
            set_cached_response(cache_key, full_response)
        return

    elif path.startswith("/api/push"):
        m = re.search(r"file=([^&]+)", path)
        if not m:
            send_http_response(conn, "400 Bad Request", "Missing file parameter")
            return
        fname = m.group(1)
        fpath = os.path.join(FILES_DIR, fname)
        with open(fpath, "wb") as f:
            f.write(body.encode("latin-1"))
        metadata[fname] = {
            "owner": username,
            "size_mb": round(len(body) / (1024 * 1024), 2),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        }
        persist_metadata()
        flush_cache(["/api/list", "/api/stats"])
        send_http_response(conn, "200 OK", f"File {fname} uploaded")
        return

    elif path.startswith("/api/delete"):
        m = re.search(r"file=([^&]+)", path)
        if not m:
            send_http_response(conn, "400 Bad Request", "Missing file parameter")
            return
        fname = m.group(1)
        if fname not in metadata:
            send_http_response(conn, "404 Not Found", "File not found")
            return
        if metadata[fname]["owner"] != username:
            send_http_response(conn, "403 Forbidden", "Permission denied")
            return
        fpath = os.path.join(FILES_DIR, fname)
        os.remove(fpath)
        del metadata[fname]
        persist_metadata()
        flush_cache(["/api/list", "/api/stats"])
        send_http_response(conn, "200 OK", f"File {fname} deleted")
        return

    else:
        send_http_response(conn, "404 Not Found", "API endpoint not found")

def handle_client(conn, addr):
    try:
        request = b""
        while b"\r\n\r\n" not in request:
            data = conn.recv(1024)
            if not data:
                break
            request += data
        if b"\r\n\r\n" not in request:
            return
        header_data, body_data = request.split(b"\r\n\r\n", 1)
        header_text = header_data.decode("utf-8", errors="ignore")
        lines = header_text.split("\r\n")
        if not lines:
            return
        req_line = lines[0]
        parts = req_line.split()
        if len(parts) < 3:
            send_http_response(conn, "400 Bad Request", "Invalid Request")
            return
        method, path, version = parts[:3]
        headers = {}
        for line in lines[1:]:
            if not line:
                continue
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()
        body = body_data
        if "Content-Length" in headers:
            cl = int(headers["Content-Length"])
            while len(body) < cl:
                data = conn.recv(1024)
                if not data:
                    break
                body += data
        body_str = body.decode("utf-8", errors="ignore")
        if path.startswith("/api/"):
            handle_api_request(conn, method, path, headers, body_str)
        else:
            serve_static_file(conn, path)
    except Exception as e:
        print("Error handling client:", e)
    finally:
        conn.close()

def run_webserver():
    web_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    web_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    web_sock.bind((HOST, WEB_PORT))
    actual_ip = get_actual_ip()
    print(f"Web server listening on {actual_ip}:{WEB_PORT}")
    web_sock.listen(5)
    while True:
        client_conn, client_addr = web_sock.accept()
        t = threading.Thread(target=handle_client, args=(client_conn, client_addr))
        t.daemon = True
        t.start()

if __name__ == "__main__":
    run_webserver()
