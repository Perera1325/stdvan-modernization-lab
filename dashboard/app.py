from flask import Flask, Response, render_template
import subprocess

app = Flask(__name__)

def stream_docker_logs():
    """
    Read Zeek logs directly from HQ container in real-time.
    """
    cmd = ["docker", "exec", "-i", "hq-core", "tail", "-f", "/conn.log"]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)

    for line in iter(process.stdout.readline, ""):
        if line.startswith("#") or line.strip() == "":
            continue
        yield f"data: {line}\n\n"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/stream")
def stream():
    return Response(stream_docker_logs(), mimetype="text/event-stream")


if __name__ == "__main__":
    app.run(debug=True, threaded=True)
