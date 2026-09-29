from flask import Flask

app = Flask(__name__)

if __name__ == "__main__":
    app.run()
    app.run(debug=False)
    app.run(host="127.0.0.1")
