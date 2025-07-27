from flask import Flask, request, render_template_string
from checker import check_strength

app = Flask(__name__)

html_template = '''
<!DOCTYPE html>
<html>
<head><title>Password Strength Checker</title></head>
<body>
  <h2>Check Your Password Strength</h2>
  <form method="POST">
    <input type="password" name="password" required>
    <button type="submit">Check</button>
  </form>
  {% if score is not none %}
    <p><strong>Strength:</strong> {{ score }}/6</p>
    <ul>
    {% for f in feedback %}
      <li>{{ f }}</li>
    {% endfor %}
    </ul>
  {% endif %}
</body>
</html>
'''

@app.route("/", methods=["GET", "POST"])
def index():
    score = None
    feedback = []
    if request.method == "POST":
        pwd = request.form["password"]
        score, feedback = check_strength(pwd)
    return render_template_string(html_template, score=score, feedback=feedback)

if __name__ == "__main__":
    app.run(debug=True)
