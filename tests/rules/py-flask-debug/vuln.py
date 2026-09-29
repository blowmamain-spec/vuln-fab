from flask import Flask

app = Flask(__name__)

if __name__ == "__main__":
    app.run(debug=True)  # vuln: py-flask-debug
    app.run(host="0.0.0.0", port=80, debug=True)  # vuln: py-flask-debug
