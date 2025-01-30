import os
import re
import random
import json
import sqlite3
import datetime
from functools import wraps

from flask import (
    Flask, jsonify, render_template, request, Response,
    redirect, url_for, session, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'replace_me_with_some_secure_key'

# Wrap the Flask app with SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")

DATABASE = 'database.db'

# The main directory containing all videos.
VIDEO_DIRECTORY = r"D:/videos"



# -----------------------
# 1. Database Connection
# -----------------------
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """
    Reads schema.sql to create/update all tables and ensures an admin user exists.
    """
    with get_db_connection() as conn:
        with open('schema.sql', 'r') as f:
            conn.executescript(f.read())

        # Ensure there's an admin user
        admin_exists = conn.execute("SELECT 1 FROM users WHERE role='admin'").fetchone()
        if not admin_exists:
            admin_pass = generate_password_hash('admin123')  # Change to a secure default
            conn.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                ('admin', admin_pass, 'admin')
            )
            conn.commit()
    print("Database initialized and admin user verified.")

# Helper function to get all normal users' progress
def get_user_progress():
    with get_db_connection() as conn:
        return conn.execute("""
            SELECT 
                u.id, 
                u.username,
                COALESCE(t.comparisons_done, 0) AS comparisons_done,
                COALESCE(t.total_comparisons, 0) AS total_comparisons
            FROM users u
            LEFT JOIN user_trees t ON u.id = t.user_id
            WHERE u.role = 'normal'
            ORDER BY u.username
        """).fetchall()

# -----------------------
# 2. Decorators
# -----------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        with get_db_connection() as conn:
            user = conn.execute("SELECT role FROM users WHERE id = ?", (session['user_id'],)).fetchone()
            if not user or user['role'] != 'admin':
                return "Access denied. Admins only.", 403
        return f(*args, **kwargs)
    return decorated_function

# -----------------------
# 3. Login & Logout
# -----------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles both admin and member logins using a hidden "type" field.
    Admin -> check hashed password
    Member -> check daily password, auto-create a new normal user if the username is unique
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        login_type = request.form['type']

        with get_db_connection() as conn:
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

            # Admin login
            if login_type == 'admin':
                if user and user['role'] == 'admin' and check_password_hash(user['password'], password):
                    session['user_id'] = user['id']
                    session['is_admin'] = True
                    flash("Admin login successful.")
                    return redirect(url_for('admin_dashboard'))
                else:
                    flash("Invalid admin credentials.")
                    return redirect(url_for('login'))

            # Committee member login
            else:
                # Check daily password
                daily_pass_row = conn.execute("""
                    SELECT password FROM daily_passwords
                    ORDER BY created_at DESC LIMIT 1
                """).fetchone()
                if not daily_pass_row or password != daily_pass_row['password']:
                    flash("Incorrect daily password.")
                    return redirect(url_for('login'))

                # If username doesn't exist, create it
                if not user:
                    try:
                        conn.execute(
                            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                            (username, None, 'normal')
                        )
                        conn.commit()
                        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
                        flash(f"New user '{username}' created.")
                    except sqlite3.IntegrityError:
                        flash("Username already exists. Please pick another.")
                        return redirect(url_for('login'))
                else:
                    # If user exists but is admin or other role, block
                    if user['role'] == 'admin':
                        flash("That username is already taken by an admin.")
                        return redirect(url_for('login'))
                    elif user['role'] != 'normal':
                        flash("Username is not available.")
                        return redirect(url_for('login'))
                    else:
                        flash("Welcome back!")

                session['user_id'] = user['id']
                session['is_admin'] = False
                return redirect(url_for('member_dashboard'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for('login'))

# -----------------------
# 4. Admin Routes
# -----------------------
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/admin')
@admin_required
def admin_dashboard():
    """
    Admin page: shows daily password, reset DB button, real-time progress chart
    """
    with get_db_connection() as conn:
        current_pass_row = conn.execute("""
            SELECT password FROM daily_passwords
            ORDER BY created_at DESC LIMIT 1
        """).fetchone()
        current_password = current_pass_row['password'] if current_pass_row else None

    user_progress = get_user_progress()
    # Convert DB rows into a Python list of dicts
    up_list = []
    for row in user_progress:
        up_list.append({
            'user_id': row['id'],
            'username': row['username'],
            'comparisons_done': row['comparisons_done'],
            'total_comparisons': row['total_comparisons']
        })

    return render_template('admin.html',
                           daily_password=current_password,
                           user_data=up_list)

@app.route('/admin/password', methods=['POST'])
@admin_required
def update_daily_password():
    new_password = ''.join(random.choices('0123456789ABCDEF', k=6))
    with get_db_connection() as conn:
        conn.execute("INSERT INTO daily_passwords (password) VALUES (?)", (new_password,))
        conn.commit()
    flash(f"New daily password generated: {new_password}")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reset_db', methods=['POST'])
@admin_required
def admin_reset_db():
    with get_db_connection() as conn:
        conn.execute("DELETE FROM users WHERE role = 'normal'")
        conn.execute("DELETE FROM auditionees")
        conn.execute("DELETE FROM user_trees")
        conn.execute("DELETE FROM votes")
        conn.commit()
    flash("Database reset.")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/remove_user/<int:user_id>', methods=['POST'])
@admin_required
def remove_user(user_id):
    with get_db_connection() as conn:
        conn.execute("DELETE FROM users WHERE id=? AND role='normal'", (user_id,))
        conn.execute("DELETE FROM user_trees WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM votes WHERE voter_id=?", (user_id,))
        conn.commit()
    flash(f"Removed user {user_id}.")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/results')
@admin_required
def view_results():
    with get_db_connection() as conn:
        final_rank = calculate_rankings(conn)
    return render_template('results.html', rankings=final_rank)

def calculate_rankings(conn):
    # A placeholder aggregator
    return [
        {"candidate": 101, "score": 85},
        {"candidate": 102, "score": 78},
        {"candidate": 103, "score": 90},
    ]

# -----------------------
# 5. API & Socket Events
# -----------------------
@app.route('/api/progress')
@admin_required
def api_get_progress():
    """
    For the admin to fetch all user progress (JSON).
    """
    rows = get_user_progress()
    data = []
    for r in rows:
        data.append({
            'user_id': r['id'],
            'username': r['username'],
            'comparisons_done': r['comparisons_done'],
            'total_comparisons': r['total_comparisons']
        })
    return jsonify({'data': data})

@socketio.on('request_progress_update')
def handle_progress_request():
    """
    A Socket.IO listener that returns the entire progress snapshot to the requester.
    The admin emits 'request_progress_update' on an interval or button click.
    """
    rows = get_user_progress()
    data = []
    for r in rows:
        data.append({
            'user_id': r['id'],
            'username': r['username'],
            'comparisons_done': r['comparisons_done'],
            'total_comparisons': r['total_comparisons']
        })
    # We emit 'progress_update' with the entire data
    emit('progress_update', {'data': data})

@app.route('/admin/add_auditionees', methods=['POST'])
@admin_required
def add_auditionees():
    """
    Reads 'candidate_count' from the form, then inserts that many new auditionees
    into the table, auto-generating candidate_number for each.
    """
    count_str = request.form.get('candidate_count', '0')
    try:
        count = int(count_str)
    except ValueError:
        flash("Invalid number of candidates.")
        return redirect(url_for('admin_dashboard'))

    if count < 1:
        flash("Candidate count must be at least 1.")
        return redirect(url_for('admin_dashboard'))

    with get_db_connection() as conn:
        # Find the current max candidate_number (or default to 0 if none)
        row = conn.execute("SELECT MAX(candidate_number) AS m FROM auditionees").fetchone()
        current_max = row['m'] if row['m'] else 0

        # Generate new candidates
        start_num = current_max + 1
        for i in range(count):
            cnum = start_num + i
            # Insert a row with candidate_number = cnum
            conn.execute("INSERT INTO auditionees (candidate_number) VALUES (?)", (cnum,))
        conn.commit()

    flash(f"Successfully added {count} new auditionees (candidate_number {start_num} through {start_num + count - 1}).")
    return redirect(url_for('admin_dashboard'))

# -----------------------
# 6. Member Routes
# -----------------------
@app.route('/member_dashboard')
@login_required
def member_dashboard():
    with get_db_connection() as conn:
        user = conn.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone()
        if user['role'] == 'admin':
            return redirect(url_for('admin_dashboard'))

        auditionees = conn.execute("SELECT * FROM auditionees ORDER BY candidate_number").fetchall()
        tree_row = conn.execute("SELECT * FROM user_trees WHERE user_id=?", (user['id'],)).fetchone()

    return render_template('dashboard.html',
                           username=user['username'],
                           auditionees=auditionees,
                           tree_data=tree_row['tree_data'] if tree_row else None)

@app.route('/member/init_tree', methods=['POST'])
@login_required
def init_user_tree():
    user_id = session['user_id']
    with get_db_connection() as conn:
        existing = conn.execute("SELECT * FROM user_trees WHERE user_id=?", (user_id,)).fetchone()
        if existing:
            flash("You already have a ranking tree.")
            return redirect(url_for('member_dashboard'))

        count_row = conn.execute("SELECT COUNT(*) as cnt FROM auditionees").fetchone()
        auditionee_count = count_row['cnt']
        import math
        total_comp = int(auditionee_count * math.log2(auditionee_count)) if auditionee_count > 1 else 0

        empty_bst = json.dumps(None)
        conn.execute("""
            INSERT INTO user_trees (user_id, tree_data, comparisons_done, total_comparisons)
            VALUES (?, ?, 0, ?)
        """, (user_id, empty_bst, total_comp))
        conn.commit()

    flash("Initialized your ranking tree.")
    return redirect(url_for('member_dashboard'))

# -----------------------
# 7. BST / Helper Logic
# -----------------------
@app.route('/member/next_comparison', methods=['GET'])
@login_required
def next_comparison():
    """
    Finds the next auditionee NOT in the user's BST and a node in the BST to compare it against.
    If BST is empty, we skip the comparison and insert as root.
    """
    user_id = session['user_id']
    with get_db_connection() as conn:
        # 1) Load the user's BST
        tree_row = conn.execute("SELECT * FROM user_trees WHERE user_id = ?", (user_id,)).fetchone()
        if not tree_row:
            flash("You need to init your ranking tree first.")
            return redirect(url_for('member_dashboard'))

        bst_data = json.loads(tree_row['tree_data'])
        # 2) Determine which auditionees are already in the BST
        existing_ids = get_bst_inorder_ids(bst_data)

        # 3) Find a new auditionee not in the BST
        candidate = conn.execute("""
            SELECT * FROM auditionees
            WHERE id NOT IN ({})
            ORDER BY candidate_number
        """.format(','.join(map(str, existing_ids)) if existing_ids else '0')
        ).fetchone()

        if not candidate:
            # All are inserted
            flash("You have inserted all auditionees. Your ranking is complete!")
            return redirect(url_for('member_dashboard'))

        # This is our "new" auditionee
        candidate_a = dict(candidate)
        candidate_a_id = candidate_a['id']

        # 4) Find a node in the BST to compare with
        compare_node = find_comparison_node(bst_data, candidate_a_id, conn)
        if not compare_node:
            # BST empty => just insert as root
            updated_bst = insert_in_bst(bst_data, candidate_a_id, "not_sure", None)
            update_user_tree(conn, user_id, updated_bst, increment=True)
            flash(f"Candidate #{candidate_a['candidate_number']} inserted as root (no comparison needed).")
            return redirect(url_for('member_dashboard'))

        # We have a node in the BST to compare with
        candidate_b_id = compare_node['candidate_id']
        candidate_b = conn.execute("SELECT * FROM auditionees WHERE id = ?", (candidate_b_id,)).fetchone()
        if not candidate_b:
            flash("Could not find the node to compare. Possibly data is out of sync.")
            return redirect(url_for('member_dashboard'))

        candidate_b = dict(candidate_b)

    # Optionally, find a relevant video name that includes both candidate_a_id & candidate_b_id
    # e.g., "3_4_15.mp4" might contain auditionees 3,4,15
    # We'll just pick the first file that includes both IDs in the name
    candidate_a_files = find_videos_for_candidate(candidate_a_id)
    candidate_b_files = find_videos_for_candidate(candidate_b_id)

    return render_template('comparison.html',
                           candidate_a=candidate_a,
                           candidate_b=candidate_b,
                           candA_videos=candidate_a_files,
                           candB_videos=candidate_b_files)

@app.route('/videos/<path:filename>')
def serve_disk_video(filename):
    """
    Streams the requested .MOV file from the disk.
    Example usage in template: url_for('serve_disk_video', filename=vid)
    """
    from flask import send_from_directory
    
    # Security check: ensure no directory traversal
    # e.g. user can't pass ../../../etc/passwd
    # For simplicity, do a basic check
    if '..' in filename or filename.startswith('/'):
        return "Invalid filename", 400

    full_path = os.path.join(VIDEO_DIRECTORY, filename)
    print(f"Attempting to serve file: {full_path}")
    if not os.path.exists(full_path):
        return "File not found", 404

    # Return as a download or as a streamed file
    # If you want partial content range requests, you might need a custom "partial_response"
    # But a simple approach:
    return send_from_directory(VIDEO_DIRECTORY, filename)


@app.route('/member/submit_comparison/<int:candidate_a_id>/<int:candidate_b_id>', methods=['POST'])
@login_required
def submit_comparison(candidate_a_id, candidate_b_id):
    """
    Takes the 3-button form: 'A_better', 'B_better', or 'not_sure'.
    Then inserts candidate_a into the BST under candidate_b's node accordingly.
    Increments comparisons_done in user_trees.
    """
    user_id = session['user_id']
    result = request.form.get('result')  # 'A_better' / 'B_better' / 'not_sure'

    with get_db_connection() as conn:
        # (Optional) log a row in 'votes'
        conn.execute("""
            INSERT INTO votes (voter_id, candidate_a_id, candidate_b_id, result)
            VALUES (?, ?, ?, ?)
        """, (user_id, candidate_a_id, candidate_b_id, result))
        conn.commit()

        # Load the BST from user_trees
        tree_row = conn.execute("SELECT * FROM user_trees WHERE user_id = ?", (user_id,)).fetchone()
        bst_data = json.loads(tree_row['tree_data'])

        # Insert the new auditionee
        updated_bst = insert_in_bst(bst_data, candidate_a_id, result, compare_node_id=candidate_b_id)
        update_user_tree(conn, user_id, updated_bst, increment=True)

    flash(f"Comparison submitted: {result}")
    return redirect(url_for('next_comparison'))


###############################################################################
# 7. BST / Helper Logic
###############################################################################

def find_comparison_node(bst_data, new_candidate_id, conn):
    """
    Depth-first approach: Return the first leaf or partially filled node that can compare
    with this new candidate. 
    If BST is empty, return None so we can insert as root.
    """
    if not bst_data:
        return None

    stack = [bst_data]
    while stack:
        node = stack.pop()
        # If this node has any free side (left, right, or tie), 
        # we can present a comparison here:
        # We'll just return the first node we find. 
        # In a more advanced approach, you'd do a balanced insertion or more complex logic.
        return node

    return None

def insert_in_bst(bst_data, new_id, result, compare_node_id=None):
    """
    Insert the new auditionee ID into the BST according to the comparison result:
    - 'A_better' => go left
    - 'B_better' => go right
    - 'not_sure' => go tie
    We'll locate the compare_node_id in the tree and attach the new node there.
    If the tree is empty, create a root node with new_id.
    """
    new_node = {
        "candidate_id": new_id,
        "left": None,
        "right": None,
        "tie": None
    }

    # If BST empty, create root
    if not bst_data:
        return new_node

    # Recursive approach to find compare_node_id
    def recurse(current):
        if not current:
            return None
        if current["candidate_id"] == compare_node_id:
            # Attach based on result
            if result == "A_better":
                if not current["left"]:
                    current["left"] = new_node
                else:
                    current["left"] = recurse(current["left"])
            elif result == "B_better":
                if not current["right"]:
                    current["right"] = new_node
                else:
                    current["right"] = recurse(current["right"])
            else:
                # not_sure => tie
                if not current["tie"]:
                    current["tie"] = new_node
                else:
                    current["tie"] = recurse(current["tie"])
            return current
        else:
            # Keep searching
            current["left"] = recurse(current["left"])
            current["right"] = recurse(current["right"])
            current["tie"] = recurse(current["tie"])
            return current

    return recurse(bst_data)

def get_bst_inorder_ids(bst_data):
    """
    Collect candidate_ids from the BST with an inorder traversal 
    (including the 'tie' branch in the middle).
    """
    result = []
    def traverse(node):
        if not node:
            return
        traverse(node["left"])
        traverse(node["tie"])
        result.append(node["candidate_id"])
        traverse(node["right"])
    if bst_data:
        traverse(bst_data)
    return result

def update_user_tree(conn, user_id, bst_data, increment=False):
    """
    After each comparison, update the user_trees table and broadcast progress to admin.
    """
    tree_json = json.dumps(bst_data)
    if increment:
        conn.execute("""
            UPDATE user_trees
            SET tree_data = ?,
                comparisons_done = comparisons_done + 1
            WHERE user_id = ?
        """, (tree_json, user_id))
    else:
        conn.execute("""
            UPDATE user_trees
            SET tree_data = ?
            WHERE user_id = ?
        """, (tree_json, user_id))
    conn.commit()

    row = conn.execute("""
        SELECT comparisons_done, total_comparisons
        FROM user_trees
        WHERE user_id = ?
    """, (user_id,)).fetchone()

    if row:
        comparisons_done = row['comparisons_done']
        total_comparisons = row['total_comparisons']
    else:
        comparisons_done = 0
        total_comparisons = 0

    user = conn.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
    username = user['username'] if user else 'Unknown'

    payload = {
        'user_id': user_id,
        'username': username,
        'comparisons_done': comparisons_done,
        'total_comparisons': total_comparisons
    }
    socketio.emit('progress_update', {'data': [payload]})


###############################################################################
# 8. Parsing Video Filenames (Optional)
###############################################################################
def find_videos_for_candidate(cand_id):
    """
    Return a list of all .MOV files in VIDEO_DIRECTORY that mention this candidate ID.
    Example: If cand_id=3 and the folder has "3_15.MOV", "3_4_5.MOV", it returns both filenames.
    """
    results = []
    
    if not os.path.isdir(VIDEO_DIRECTORY):
        return results  # Directory doesn't exist
    
    for filename in os.listdir(VIDEO_DIRECTORY):
        if not filename.lower().endswith(".MOV"):
            continue
        # Extract digits from the filename
        numbers = re.findall(r'\d+', filename)
        nums = [int(x) for x in numbers]
        if cand_id in nums:
            results.append(filename)
    
    return results

@app.route('/videos/test')
def test_video():
    from flask import send_from_directory
    return send_from_directory("D:\\videos", "1_2_3 (2).MOV")

# -----------------------
# 8. Run the App
# -----------------------
if __name__ == '__main__':
    init_db()
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
