from flask import Flask, render_template, request, redirect, url_for, session, jsonify, g
from flask_bcrypt import Bcrypt
from flask_session import Session
from flask_cors import CORS
import sqlite3, json, os, re
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")
app.config["SESSION_TYPE"] = "filesystem"
app.config["PERMANENT_SESSION_LIFETIME"] = 3600000  # 1 hour session lifetime

bcrypt = Bcrypt(app)
Session(app)
CORS(app)  # Enable CORS for all routes

DB = "eduquiz.db"

# ---------- DATABASE ----------
def get_db():
    """Get database connection with context management"""
    if 'db' not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    """Close database connection at the end of request"""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Initialize database with proper schema"""
    with app.app_context():
        db = get_db()
        c = db.cursor()

        # Admin
        c.execute("""CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )""")

        # Questions
        c.execute("""CREATE TABLE IF NOT EXISTS questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT CHECK(type IN ('mcq','open')) NOT NULL,
            question_text TEXT NOT NULL,
            points INTEGER NOT NULL DEFAULT 1,
            correct_answer TEXT,
            keywords TEXT,
            options TEXT
        )""")

        # Responses
        c.execute("""CREATE TABLE IF NOT EXISTS responses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_name TEXT NOT NULL,
            question_id INTEGER NOT NULL,
            answer TEXT NOT NULL,
            score REAL NOT NULL,
            submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(question_id) REFERENCES questions(id) ON DELETE CASCADE
        )""")

        # Create index for better performance
        c.execute("CREATE INDEX IF NOT EXISTS idx_responses_student ON responses(student_name)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_responses_question ON responses(question_id)")

        # Check if admin exists and has the correct password
        admin = c.execute("SELECT * FROM admin WHERE username = ?", ("admin",)).fetchone()
        
        # If admin exists, update with correct password
        if admin:
            pw_hash = bcrypt.generate_password_hash("admin123").decode("utf-8")
            c.execute("UPDATE admin SET password_hash = ? WHERE username = ?", (pw_hash, "admin"))
            print("Admin password updated successfully")
        else:
            # Create admin with correct password
            pw_hash = bcrypt.generate_password_hash("admin123").decode("utf-8")
            c.execute("INSERT INTO admin(username,password_hash) VALUES(?,?)", ("admin", pw_hash))
            print("Admin account created successfully")

        # Add sample questions if none exist
        question_count = c.execute("SELECT COUNT(*) FROM questions").fetchone()[0]
        if question_count == 0:
            # Sample MCQ
            c.execute("""INSERT INTO questions (type, question_text, points, correct_answer, options) 
                         VALUES (?, ?, ?, ?, ?)""",
                     ("mcq", "What is the capital of France?", 1, "Paris", 
                      json.dumps(["London", "Paris", "Berlin", "Madrid"])))
            
            # Sample Open-ended
            c.execute("""INSERT INTO questions (type, question_text, points, correct_answer, keywords) 
                         VALUES (?, ?, ?, ?, ?)""",
                     ("open", "Explain the concept of photosynthesis.", 3, 
                      "Process by which plants convert sunlight into energy", 
                      "photosynthesis, plants, sunlight, energy, chlorophyll"))
            
            print("Sample questions added successfully")

        db.commit()

# ---------- DECORATORS ----------
def admin_required(f):
    """Decorator to require admin authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("admin"):
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function

# ---------- HELPER FUNCTIONS ----------
def calculate_open_question_score(answer, keywords, points):
    """Calculate score for open-ended questions based on keyword matching"""
    if not keywords:
        return 0
    
    try:
        keyword_list = [k.strip().lower() for k in keywords.split(",")]
        answer_words = re.findall(r'\b\w+\b', answer.lower())
        
        # Count matching keywords
        matches = sum(1 for keyword in keyword_list if keyword in answer_words)
        
        # Calculate score based on percentage of keywords found
        if matches > 0:
            match_percentage = matches / len(keyword_list)
            return round(match_percentage * points, 2)
        return 0
    except:
        return 0

# ---------- ROUTES ----------
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/quiz")
def quiz_page():
    return render_template("quiz.html")

@app.route("/admin")
def admin_login():
    if session.get("admin"):
        return redirect(url_for("admin_dashboard"))
    return render_template("admin_login.html")

@app.route("/admin/dashboard")
def admin_dashboard():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
    return render_template("admin_dashboard.html")

# ---------- API ----------
@app.route("/api/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        if not data or "username" not in data or "password" not in data:
            return jsonify({"success": False, "message": "Invalid request"}), 400
        
        db = get_db()
        user = db.execute("SELECT * FROM admin WHERE username = ?", (data["username"],)).fetchone()
        
        print(f"Login attempt: {data['username']}")  # Debug
        print(f"User found: {bool(user)}")  # Debug
        
        if user:
            print(f"Password check: {data['password']} vs hash {user['password_hash']}")  # Debug
            password_valid = bcrypt.check_password_hash(user["password_hash"], data["password"])
            print(f"Password valid: {password_valid}")  # Debug
            
            if password_valid:
                session["admin"] = True
                session.permanent = True
                return jsonify({"success": True})
        
        return jsonify({"success": False, "message": "Invalid credentials"}), 401
    except Exception as e:
        print(f"Login error: {e}")  # Debug
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/api/logout")
def logout():
    session.pop("admin", None)
    return jsonify({"success": True})

@app.route("/api/questions", methods=["GET", "POST"])
def questions():
    try:
        if request.method == "GET":
            db = get_db()
            rows = db.execute("SELECT id, type, question_text, points, correct_answer, keywords, options FROM questions").fetchall()
            
            result = []
            for r in rows:
                result.append({
                    "id": r["id"],
                    "type": r["type"],
                    "question_text": r["question_text"],
                    "points": r["points"],
                    "correct_answer": r["correct_answer"],
                    "keywords": r["keywords"],
                    "options": json.loads(r["options"]) if r["options"] else None
                })
            return jsonify(result)
        
        else:  # POST admin adds
            if not session.get("admin"):
                return jsonify({"error": "Unauthorized"}), 403
            
            data = request.get_json()
            if not data or "question_text" not in data or "type" not in data:
                return jsonify({"error": "Missing required fields"}), 400
            
            # Validate question type
            if data["type"] not in ["mcq", "open"]:
                return jsonify({"error": "Invalid question type"}), 400
            
            # Validate points
            points = data.get("points", 1)
            if not isinstance(points, int) or points < 1:
                points = 1
            
            # Prepare options for MCQ
            options = None
            if data["type"] == "mcq":
                if "options" not in data or not isinstance(data["options"], list) or len(data["options"]) < 2:
                    return jsonify({"error": "MCQ questions require at least 2 options"}), 400
                options = json.dumps(data["options"])
            
            # Prepare correct answer and keywords
            correct_answer = data.get("correct_answer", "")
            keywords = data.get("keywords", "")
            
            db = get_db()
            db.execute("""INSERT INTO questions(type, question_text, points, correct_answer, keywords, options)
                        VALUES(?,?,?,?,?,?)""",
                    (data["type"], data["question_text"], points, correct_answer, keywords, options))
            db.commit()
            
            return jsonify({"success": True, "message": "Question added successfully"})
    
    except Exception as e:
        return jsonify({"error": "Server error"}), 500

@app.route("/api/questions/<int:question_id>", methods=["PUT", "DELETE"])
@admin_required
def question_operations(question_id):
    try:
        db = get_db()
        
        if request.method == "PUT":
            data = request.get_json()
            if not data:
                return jsonify({"error": "No data provided"}), 400
            
            # Build update query dynamically based on provided fields
            update_fields = []
            params = []
            
            if "question_text" in data:
                update_fields.append("question_text = ?")
                params.append(data["question_text"])
            
            if "points" in data:
                update_fields.append("points = ?")
                params.append(data["points"])
            
            if "correct_answer" in data:
                update_fields.append("correct_answer = ?")
                params.append(data["correct_answer"])
            
            if "keywords" in data:
                update_fields.append("keywords = ?")
                params.append(data["keywords"])
            
            if "options" in data:
                update_fields.append("options = ?")
                params.append(json.dumps(data["options"]))
            
            if not update_fields:
                return jsonify({"error": "No valid fields to update"}), 400
            
            params.append(question_id)
            query = f"UPDATE questions SET {', '.join(update_fields)} WHERE id = ?"
            
            result = db.execute(query, params)
            db.commit()
            
            if result.rowcount == 0:
                return jsonify({"error": "Question not found"}), 404
            
            return jsonify({"success": True, "message": "Question updated successfully"})
        
        elif request.method == "DELETE":
            result = db.execute("DELETE FROM questions WHERE id = ?", (question_id,))
            db.commit()
            
            if result.rowcount == 0:
                return jsonify({"error": "Question not found"}), 404
            
            return jsonify({"success": True, "message": "Question deleted successfully"})
    
    except Exception as e:
        return jsonify({"error": "Server error"}), 500

@app.route("/api/submit", methods=["POST"])
def submit():
    try:
        data = request.get_json()
        if not data or "student" not in data or "answers" not in data:
            return jsonify({"error": "Invalid request"}), 400
        
        student = data["student"].strip()
        if not student:
            return jsonify({"error": "Student name is required"}), 400
        
        answers = data["answers"]
        if not isinstance(answers, list) or len(answers) == 0:
            return jsonify({"error": "No answers provided"}), 400
        
        db = get_db()
        total_score = 0
        max_score = 0
        
        for ans in answers:
            # Get the question details
            question = db.execute(
                "SELECT type, points, correct_answer, keywords FROM questions WHERE id = ?", 
                (ans["id"],)
            ).fetchone()
            
            if not question:
                continue  # Skip if question doesn't exist
            
            score = 0
            answer_text = ans.get("answer", "").strip()
            max_score += question["points"]
            
            if question["type"] == "mcq":
                # For MCQ, check if answer matches correct answer
                if answer_text.lower() == question["correct_answer"].lower():
                    score = question["points"]
            else:
                # For open questions, calculate score based on keywords
                score = calculate_open_question_score(
                    answer_text, 
                    question["keywords"], 
                    question["points"]
                )
            
            total_score += score
            
            # Store response with calculated score
            db.execute(
                "INSERT INTO responses(student_name, question_id, answer, score) VALUES(?,?,?,?)",
                (student, ans["id"], answer_text, score)
            )
        
        db.commit()
        return jsonify({
            "success": True, 
            "message": "Quiz submitted successfully",
            "score": total_score,
            "max_score": max_score,
            "percentage": round((total_score / max_score) * 100, 2) if max_score > 0 else 0
        })
    
    except Exception as e:
        return jsonify({"error": "Server error"}), 500

@app.route("/api/responses")
@admin_required
def get_responses():
    try:
        db = get_db()
        
        # Get all responses with question details
        rows = db.execute("""
            SELECT r.student_name, r.answer, r.score, r.submitted_at,
                   q.question_text, q.type, q.points
            FROM responses r
            JOIN questions q ON r.question_id = q.id
            ORDER BY r.submitted_at DESC
        """).fetchall()
        
        result = []
        for r in rows:
            result.append({
                "student_name": r["student_name"],
                "question": r["question_text"],
                "type": r["type"],
                "answer": r["answer"],
                "score": r["score"],
                "max_score": r["points"],
                "submitted_at": r["submitted_at"]
            })
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({"error": "Server error"}), 500

@app.route("/api/results/<student_name>")
def get_student_results(student_name):
    try:
        db = get_db()
        
        # Get all responses for a specific student
        rows = db.execute("""
            SELECT r.answer, r.score, r.submitted_at,
                   q.question_text, q.type, q.points, q.correct_answer
            FROM responses r
            JOIN questions q ON r.question_id = q.id
            WHERE r.student_name = ?
            ORDER BY r.submitted_at DESC
        """, (student_name,)).fetchall()
        
        if not rows:
            return jsonify({"error": "No results found for this student"}), 404
        
        result = {
            "student_name": student_name,
            "responses": [],
            "total_score": 0,
            "max_possible_score": 0
        }
        
        for r in rows:
            result["responses"].append({
                "question": r["question_text"],
                "type": r["type"],
                "answer": r["answer"],
                "score": r["score"],
                "max_score": r["points"],
                "correct_answer": r["correct_answer"],
                "submitted_at": r["submitted_at"]
            })
            result["total_score"] += r["score"]
            result["max_possible_score"] += r["points"]
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({"error": "Server error"}), 500

# Register teardown context
app.teardown_appcontext(close_db)

if __name__ == "__main__":
    # Delete existing database to ensure clean start (optional)
    if os.path.exists(DB):
        os.remove(DB)
        print("Old database removed")
    
    init_db()
    app.run(debug=True)