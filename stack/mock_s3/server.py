import http.server
import json
import os
import socketserver

PORT = 9000
IAM_DENY_FLAG = "/tmp/iam_s3_denied"

class MockS3Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # Check if IAM access is currently denied
        is_denied = os.path.exists(IAM_DENY_FLAG) or os.getenv("IAM_ACCESS_DENIED", "0") == "1"

        if is_denied:
            xml_error = """<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>AccessDenied</Code>
  <Message>Access Denied: User role lacks s3:GetObject on resource arn:aws:s3:::triageforge-assets/*</Message>
  <Resource>arn:aws:s3:::triageforge-assets/app-config.json</Resource>
  <RequestId>TF-ERR-403-IAM-DENY</RequestId>
  <HostId>triageforge-s3-mock</HostId>
</Error>"""
            self.send_response(403)
            self.send_header("Content-Type", "application/xml")
            self.send_header("x-amz-request-id", "TF-ERR-403-IAM-DENY")
            self.end_headers()
            self.wfile.write(xml_error.encode("utf-8"))
            return

        payload = {
            "bucket": "triageforge-assets",
            "key": "app-config.json",
            "status": "active",
            "version": "1.0",
            "storage_class": "STANDARD",
        }
        resp_data = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp_data)))
        self.end_headers()
        self.wfile.write(resp_data)

    def log_message(self, format, *args):
        print(f"[MOCK-S3] {self.address_string()} - {format % args}", flush=True)

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), MockS3Handler) as httpd:
        print(f"[MOCK-S3] Serving mock AWS S3 on port {PORT}...", flush=True)
        httpd.serve_forever()
