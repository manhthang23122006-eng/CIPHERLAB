from flask import Flask, render_template, request, redirect, session, jsonify
import sqlite3
import hashlib
import os

# ==============================
# IMPORT CÁC THUẬT TOÁN
# ==============================

from crypto.rsa import (
    generate_keys as generate_rsa_keys,
    encrypt_rsa,
    decrypt_rsa
)

from crypto.elgamal import (
    generate_keys as generate_elgamal_keys,
    encrypt_elgamal,
    decrypt_elgamal
)

from crypto.aes import (
    encrypt_aes,
    decrypt_aes
)

from crypto.des import (
    encrypt_des,
    decrypt_des
)


app = Flask(__name__)

app.secret_key = "cipherlab_secret_key"

# ==============================
# AUTO ACTIVITY LOGGER
# ==============================

@app.after_request
def log_activity(response):

    try:

        if request.method == "POST" and response.status_code == 200:

            path = request.path

            algorithm = None
            action = None

            # ==============================
            # DES
            # ==============================

            if path == "/des/encrypt":

                algorithm = "DES"
                action = "Encrypt"

            elif path == "/des/decrypt":

                algorithm = "DES"
                action = "Decrypt"

            # ==============================
            # AES
            # ==============================

            elif path == "/aes/encrypt":

                algorithm = "AES"
                action = "Encrypt"

            elif path == "/aes/decrypt":

                algorithm = "AES"
                action = "Decrypt"

            # ==============================
            # RSA
            # ==============================

            elif path == "/rsa/generate":

                algorithm = "RSA"
                action = "Generate Key"

            elif path == "/rsa/encrypt":

                algorithm = "RSA"
                action = "Encrypt"

            elif path == "/rsa/decrypt":

                algorithm = "RSA"
                action = "Decrypt"

            # ==============================
            # ELGAMAL
            # ==============================

            elif path == "/elgamal/generate":

                algorithm = "ElGamal"
                action = "Generate Key"

            elif path == "/elgamal/encrypt":

                algorithm = "ElGamal"
                action = "Encrypt"

            elif path == "/elgamal/decrypt":

                algorithm = "ElGamal"
                action = "Decrypt"

            # ==============================
            # SHA-256
            # ==============================

            elif path == "/sha256/hash":

                algorithm = "SHA-256"
                action = "Hash"

            # ==============================
            # MD5
            # ==============================

            elif path == "/md5/hash":

                algorithm = "MD5"
                action = "Hash"


            # ==============================
            # SAVE
            # ==============================

            if algorithm and action:

                save_activity(
                    algorithm,
                    action
                )

    except Exception:
        pass

    return response


# ==============================
# DATABASE
# ==============================

# ==============================
# DATABASE
# ==============================

def get_db():

    conn = sqlite3.connect("database.db")

    conn.row_factory = sqlite3.Row

    return conn


def init_db():

    conn = get_db()

    # ==============================
    # USERS
    # ==============================

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    # ==============================
    # ACTIVITY LOGS
    # ==============================

    conn.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            algorithm TEXT NOT NULL,
            action TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()

    conn.close()


# ==============================
# SAVE ACTIVITY
# ==============================

def save_activity(algorithm, action):

    username = session.get("username")

    if not username:
        return

    try:

        conn = get_db()

        conn.execute("""
            INSERT INTO activity_logs
            (username, algorithm, action)
            VALUES (?, ?, ?)
        """, (
            username,
            algorithm,
            action
        ))

        conn.commit()

        conn.close()

    except Exception:
        pass


# ==============================
# TRANG CHỦ
# ==============================

@app.route("/")
def home():

    return render_template("index.html")


# ==============================
# ĐĂNG NHẬP
# ==============================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]

        password = request.form["password"]

        conn = get_db()

        user = conn.execute(
            """
            SELECT * FROM users
            WHERE username = ?
            AND password = ?
            """,
            (username, password)
        ).fetchone()

        conn.close()

        if user:

            session["username"] = user["username"]

            return redirect("/dashboard")

        return "Sai tên đăng nhập hoặc mật khẩu!"

    return render_template("login.html")


# ==============================
# ĐĂNG KÝ
# ==============================

@app.route("/register", methods=["POST"])
def register():

    username = request.form["username"]

    email = request.form["email"]

    password = request.form["password"]

    conn = get_db()

    try:

        conn.execute(
            """
            INSERT INTO users
            (username, email, password)
            VALUES (?, ?, ?)
            """,
            (username, email, password)
        )

        conn.commit()

    except sqlite3.IntegrityError:

        conn.close()

        return "Tên đăng nhập hoặc email đã tồn tại!"

    conn.close()

    return redirect("/login")


# ==============================
# DASHBOARD
# ==============================

@app.route("/dashboard")
def dashboard():

    if "username" not in session:

        return redirect("/login")

    return render_template("dashboard.html")


# ==============================
# DES LABORATORY
# ==============================

@app.route("/des")
def des():

    if "username" not in session:

        return redirect("/login")

    return render_template("des.html")


# ==============================
# DES ENCRYPT
# ==============================

@app.route("/des/encrypt", methods=["POST"])
def des_encrypt():

    data = request.get_json()

    text = data.get("text", "")

    key = data.get("key", "")

    if not text or not key:

        return jsonify({
            "result": "Vui lòng nhập văn bản và khóa!"
        })

    try:

        result = encrypt_des(
            text,
            key
        )

        return jsonify({
            "result": result
        })

    except Exception as e:

        return jsonify({
            "result": "Lỗi: " + str(e)
        })


# ==============================
# DES DECRYPT
# ==============================

@app.route("/des/decrypt", methods=["POST"])
def des_decrypt():

    data = request.get_json()

    text = data.get("text", "")

    key = data.get("key", "")

    if not text or not key:

        return jsonify({
            "result": "Vui lòng nhập dữ liệu và khóa!"
        })

    try:

        result = decrypt_des(
            text,
            key
        )

        return jsonify({
            "result": result
        })

    except Exception:

        return jsonify({
            "result":
            "Không thể giải mã! Hãy kiểm tra ciphertext và khóa."
        })


# ==============================
# RSA LABORATORY
# ==============================

@app.route("/rsa")
def rsa():

    return render_template("rsa.html")


# ==============================
# GENERATE RSA KEYS
# ==============================

@app.route("/rsa/generate", methods=["POST"])
def rsa_generate():

    try:

        public_key, private_key = generate_rsa_keys()

        return jsonify({
            "public_key": public_key,
            "private_key": private_key
        })

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500


# ==============================
# RSA ENCRYPT
# ==============================

@app.route("/rsa/encrypt", methods=["POST"])
def rsa_encrypt():

    data = request.get_json()

    text = data.get("text", "")

    public_key = data.get("public_key", "")

    if not text or not public_key:

        return jsonify({
            "result":
            "Vui lòng nhập văn bản và Public Key!"
        })

    try:

        result = encrypt_rsa(
            text,
            public_key
        )

        return jsonify({
            "result": result
        })

    except Exception as e:

        return jsonify({
            "result":
            "Lỗi mã hóa: " + str(e)
        })


# ==============================
# RSA DECRYPT
# ==============================

@app.route("/rsa/decrypt", methods=["POST"])
def rsa_decrypt():

    data = request.get_json()

    ciphertext = data.get(
        "ciphertext",
        ""
    )

    private_key = data.get(
        "private_key",
        ""
    )

    if not ciphertext or not private_key:

        return jsonify({
            "result":
            "Vui lòng nhập ciphertext và Private Key!"
        })

    try:

        result = decrypt_rsa(
            ciphertext,
            private_key
        )

        return jsonify({
            "result": result
        })

    except Exception as e:

        return jsonify({
            "result":
            "Lỗi giải mã: " + str(e)
        })


# ==============================
# ELGAMAL LABORATORY
# ==============================

# ==============================
# ELGAMAL LABORATORY
# ==============================

@app.route("/elgamal")
def elgamal():

    return render_template("elgamal.html")


# ==============================
# GENERATE ELGAMAL KEYS
# ==============================

@app.route("/elgamal/generate", methods=["POST"])
def elgamal_generate():

    try:

        keys = generate_elgamal_keys()

        # Lưu khóa vào session
        session["elgamal_keys"] = keys

        return jsonify({
            "p": keys["p"],
            "g": keys["g"],
            "public_key": keys["public_key"],
            "private_key": keys["private_key"]
        })

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500


# ==============================
# ELGAMAL ENCRYPT
# ==============================

@app.route("/elgamal/encrypt", methods=["POST"])
def elgamal_encrypt():

    try:

        data = request.get_json()

        text = data.get("text", "")

        if not text:

            return jsonify({
                "error": "Vui lòng nhập văn bản!"
            })

        # Lấy khóa đã tạo từ session
        keys = session.get("elgamal_keys")

        if not keys:

            return jsonify({
                "error": "Vui lòng tạo cặp khóa trước!"
            })

        result = encrypt_elgamal(
            text,
            keys
        )

        return jsonify({
            "result": result
        })

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500


# ==============================
# ELGAMAL DECRYPT
# ==============================

@app.route("/elgamal/decrypt", methods=["POST"])
def elgamal_decrypt():

    try:

        data = request.get_json()

        ciphertext = data.get(
            "ciphertext",
            ""
        )

        if not ciphertext:

            return jsonify({
                "error": "Vui lòng nhập ciphertext!"
            })

        # Lấy khóa đã tạo từ session
        keys = session.get("elgamal_keys")

        if not keys:

            return jsonify({
                "error": "Vui lòng tạo cặp khóa trước!"
            })

        result = decrypt_elgamal(
            ciphertext,
            keys
        )

        return jsonify({
            "result": result
        })

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500


# ==============================
# ĐĂNG XUẤT
# ==============================

# ==============================
# ACTIVITY HISTORY
# ==============================

@app.route("/history")
def history():

    if "username" not in session:

        return redirect("/login")


    conn = get_db()

    activities = conn.execute("""
        SELECT
            algorithm,
            action,
            created_at
        FROM activity_logs
        WHERE username = ?
        ORDER BY id DESC
        LIMIT 50
    """, (
        session["username"],
    )).fetchall()


    conn.close()


    return render_template(
        "history.html",
        activities=activities
    )

# ==============================
# STATISTICS
# ==============================

@app.route("/statistics")
def statistics():

    if "username" not in session:
        return redirect("/login")

    conn = get_db()

    username = session["username"]

    # Tổng số hoạt động
    total = conn.execute("""
        SELECT COUNT(*) AS total
        FROM activity_logs
        WHERE username = ?
    """, (username,)).fetchone()["total"]

    # Tổng số Encrypt
    encrypt_count = conn.execute("""
        SELECT COUNT(*) AS total
        FROM activity_logs
        WHERE username = ?
        AND action = 'Encrypt'
    """, (username,)).fetchone()["total"]

    # Tổng số Decrypt
    decrypt_count = conn.execute("""
        SELECT COUNT(*) AS total
        FROM activity_logs
        WHERE username = ?
        AND action = 'Decrypt'
    """, (username,)).fetchone()["total"]

    # Tổng số Hash
    hash_count = conn.execute("""
        SELECT COUNT(*) AS total
        FROM activity_logs
        WHERE username = ?
        AND action = 'Hash'
    """, (username,)).fetchone()["total"]

    # Tổng số Generate Key
    key_count = conn.execute("""
        SELECT COUNT(*) AS total
        FROM activity_logs
        WHERE username = ?
        AND action = 'Generate Key'
    """, (username,)).fetchone()["total"]

    # Thống kê theo thuật toán
    algorithm_stats = conn.execute("""
        SELECT
            algorithm,
            COUNT(*) AS total
        FROM activity_logs
        WHERE username = ?
        GROUP BY algorithm
        ORDER BY total DESC
    """, (username,)).fetchall()

    # Thống kê theo thao tác
    action_stats = conn.execute("""
        SELECT
            action,
            COUNT(*) AS total
        FROM activity_logs
        WHERE username = ?
        GROUP BY action
        ORDER BY total DESC
    """, (username,)).fetchall()

    # Thuật toán sử dụng nhiều nhất
    most_used = None

    if algorithm_stats:
        most_used = algorithm_stats[0]["algorithm"]

    conn.close()

    return render_template(
        "statistics.html",
        total=total,
        encrypt_count=encrypt_count,
        decrypt_count=decrypt_count,
        hash_count=hash_count,
        key_count=key_count,
        algorithm_stats=algorithm_stats,
        action_stats=action_stats,
        most_used=most_used
    )

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


# ==============================
# AES LABORATORY
# ==============================

@app.route("/aes")
def aes():

    if "username" not in session:

        return redirect("/login")

    return render_template("aes.html")


# ==============================
# AES ENCRYPT
# ==============================

@app.route("/aes/encrypt", methods=["POST"])
def aes_encrypt():

    data = request.get_json()

    text = data.get(
        "text",
        ""
    )

    key = data.get(
        "key",
        ""
    )

    if not text or not key:

        return jsonify({
            "result":
            "Vui lòng nhập văn bản và khóa!"
        })

    try:

        result = encrypt_aes(
            text,
            key
        )

        return jsonify({
            "result": result
        })

    except Exception as e:

        return jsonify({
            "result":
            "Lỗi: " + str(e)
        })


# ==============================
# AES DECRYPT
# ==============================

@app.route("/aes/decrypt", methods=["POST"])
def aes_decrypt():

    data = request.get_json()

    text = data.get(
        "text",
        ""
    )

    key = data.get(
        "key",
        ""
    )

    if not text or not key:

        return jsonify({
            "result":
            "Vui lòng nhập dữ liệu và khóa!"
        })

    try:

        result = decrypt_aes(
            text,
            key
        )

        return jsonify({
            "result": result
        })

    except Exception:

        return jsonify({
            "result":
            "Không thể giải mã! Hãy kiểm tra ciphertext và khóa."
        })


# ==============================
# CHẠY SERVER
# ==============================

# ==============================
# SHA-256 LABORATORY
# ==============================

@app.route("/sha256")
def sha256():
    return render_template("sha256.html")


@app.route("/sha256/hash", methods=["POST"])
def sha256_hash():

    try:

        data = request.get_json()

        text = data.get("text", "")

        if not text:

            return jsonify({
                "error": "Vui lòng nhập văn bản!"
            })

        hash_result = hashlib.sha256(
            text.encode("utf-8")
        ).hexdigest()

        return jsonify({
            "result": hash_result
        })

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500

# ==============================
# MD5 LABORATORY
# ==============================

@app.route("/md5")
def md5():
    return render_template("md5.html")


@app.route("/md5/hash", methods=["POST"])
def md5_hash():

    try:

        data = request.get_json()

        text = data.get("text", "")

        if not text:

            return jsonify({
                "error": "Vui lòng nhập văn bản!"
            })

        hash_result = hashlib.md5(
            text.encode("utf-8")
        ).hexdigest()

        return jsonify({
            "result": hash_result
        })

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500




# ==============================
# QUIZ
# ==============================

@app.route("/quiz")
def quiz():
    return render_template("quiz.html")


@app.route("/quiz/submit", methods=["POST"])
def quiz_submit():

    try:

        data = request.get_json()

        answers = data.get("answers", {})

        correct_answers = {
            "q1": "B",
            "q2": "C",
            "q3": "A",
            "q4": "D",
            "q5": "B",
            "q6": "C",
            "q7": "A",
            "q8": "D",
            "q9": "B",
            "q10": "C"
        }

        score = 0

        for question, correct in correct_answers.items():

            if answers.get(question) == correct:
                score += 1

        total = len(correct_answers)

        percent = int((score / total) * 100)

        # Lưu điểm Quiz vào session
        session["quiz_score"] = percent
        session["quiz_correct"] = score
        session["quiz_total"] = total

        return jsonify({
            "success": True,
            "score": score,
            "total": total,
            "percent": percent
        })

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ==============================
# SETTINGS
# ==============================

@app.route("/settings")
def settings():
    return render_template("settings.html")


# ==============================
# RUN APPLICATION
# ==============================

if __name__ == "__main__":

    init_db()

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=True
    )