"""Flask web interface for the password strength checker.

Run locally and open http://127.0.0.1:5000/. Passwords are evaluated in
memory and never stored or logged.

Usage:
    python InterfaceApp.py
"""

from __future__ import annotations

from flask import Flask, render_template_string, request

from checker import check_strength

app = Flask(__name__)

PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Password Strength Checker</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 32rem; margin: 3rem auto; padding: 0 1rem; }
    input { font-size: 1rem; padding: .5rem; width: 70%; }
    button { font-size: 1rem; padding: .5rem 1rem; }
    .bar { height: 10px; border-radius: 5px; background: #e5e7eb; margin: 1rem 0; overflow: hidden; }
    .fill { height: 100%; transition: width .2s; }
    ul { color: #374151; }
  </style>
</head>
<body>
  <h2>Password Strength Checker</h2>
  <form method="post">
    <input type="password" name="password" autofocus required>
    <button type="submit">Check</button>
  </form>
  {% if result %}
    <p><strong>{{ result.label }}</strong> — {{ result.score }}/100</p>
    <div class="bar"><div class="fill" style="width: {{ result.score }}%; background: {{ color }};"></div></div>
    <ul>{% for item in result.feedback %}<li>{{ item }}</li>{% endfor %}</ul>
  {% endif %}
</body>
</html>
"""


def _color(score: int) -> str:
    if score >= 70:
        return "#16a34a"
    if score >= 45:
        return "#ca8a04"
    return "#dc2626"


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    color = "#e5e7eb"
    if request.method == "POST":
        result = check_strength(request.form.get("password", ""))
        color = _color(result.score)
    return render_template_string(PAGE, result=result, color=color)


if __name__ == "__main__":
    # debug=False: the Werkzeug debugger exposes an interactive console that
    # allows remote code execution if the app is ever reachable off-localhost.
    app.run(host="127.0.0.1", port=5000, debug=False)
