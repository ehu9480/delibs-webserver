import os
import re
import random
import json
import math
import sqlite3
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit

###############################################################################
# CONFIG & DB SETUP
###############################################################################
app = Flask(__name__)
app.config['SECRET_KEY'] = 'replace_me_with_some_secure_key'

socketio = SocketIO(app, cors_allowed_origins="*")
DATABASE = 'database.db'

# Where the videos are stored (if you're serving them from disk)
VIDEO_DIRECTORY = r"C:\sp25_auditions"

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
            admin_pass = generate_password_hash('admin123')
            conn.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                ('admin', admin_pass, 'admin')
            )
            conn.commit()
    print("Database initialized and admin user verified.")

###############################################################################
# DECORATORS
###############################################################################
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
            user = conn.execute("SELECT role FROM users WHERE id=?", (session['user_id'],)).fetchone()
            if not user or user['role'] != 'admin':
                return "Access denied. Admins only.", 403
        return f(*args, **kwargs)
    return decorated_function

###############################################################################
# HELPER: Emitting progress_update
###############################################################################
def emit_progress_update(user_id):
    """
    Broadcast the user’s comparisons_done & total_comparisons to admin chart
    """
    with get_db_connection() as conn:
        row = conn.execute("""
            SELECT comparisons_done, total_comparisons
            FROM user_rankings
            WHERE user_id=?
        """, (user_id,)).fetchone()

    if row:
        comparisons_done = row['comparisons_done']
        total_comparisons = row['total_comparisons']
    else:
        comparisons_done = 0
        total_comparisons = 0

    with get_db_connection() as conn:
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
# AUTH & LOGIN
###############################################################################
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        login_type = request.form.get('type')

        with get_db_connection() as conn:
            user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

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
            else:
                # 1) Check daily password
                row = conn.execute("SELECT password FROM daily_passwords ORDER BY created_at DESC LIMIT 1").fetchone()
                if not row or password != row['password']:
                    flash("Incorrect daily password.")
                    return redirect(url_for('login'))

                # 2) If username doesn't exist, create user
                if not user:
                    try:
                        conn.execute("""
                            INSERT INTO users (username, password, role)
                            VALUES (?, ?, ?)
                        """, (username, None, 'normal'))
                        conn.commit()
                        # re-fetch the newly created user
                        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

                        # 3) Now assign them some candidates so they have something to do
                        assign_candidates_to_new_user(conn, user['id'])

                        flash(f"New user '{username}' created and assigned some candidates.")
                    except sqlite3.IntegrityError:
                        flash("Username already exists. Pick another.")
                        return redirect(url_for('login'))
                else:
                    # If user already exists, just check role
                    if user['role'] == 'admin':
                        flash("That username is taken by admin.")
                        return redirect(url_for('login'))
                    elif user['role'] != 'normal':
                        flash("Username is not available.")
                        return redirect(url_for('login'))
                    else:
                        flash("Welcome back!")

                # 4) Log them in
                session['user_id'] = user['id']
                session['is_admin'] = False
                return redirect(url_for('member_dashboard'))

    # if GET or no form submission
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for('login'))

def assign_candidates_to_new_user(conn, user_id):
    """
    Assign some candidates to this new user, so they don't see 'All assigned processed!' on first login.
    Also create a user_rankings row for them.
    """

    # 1) how many auditionees total?
    all_candidates = conn.execute("SELECT id FROM auditionees").fetchall()
    cand_ids = [row['id'] for row in all_candidates]
    total_cands = len(cand_ids)
    if total_cands == 0:
        # No auditionees exist
        return

    # 2) Decide how many we want them to see, e.g. 30%
    subset_size = max(1, int(0.3 * total_cands))  # or a fixed # like 10
    chosen = random.sample(cand_ids, subset_size)

    # 3) Insert into assignments
    for cid in chosen:
        conn.execute("INSERT INTO assignments (user_id, candidate_id) VALUES (?,?)",
                     (user_id, cid))

    # 4) Also create or reset user_rankings row. The user has assigned_count = subset_size
    conn.execute("""
        INSERT INTO user_rankings (user_id, ranking_data, comparisons_done, total_comparisons)
        VALUES (?, ?, 0, ?)
    """, (user_id, json.dumps([]), subset_size))
    conn.commit()

###############################################################################
# ADMIN ROUTES
###############################################################################
@app.route('/admin')
@admin_required
def admin_dashboard():
    with get_db_connection() as conn:
        current_pass = conn.execute("""
            SELECT password FROM daily_passwords ORDER BY created_at DESC LIMIT 1
        """).fetchone()

        # Also fetch total auditionees from DB or from config
        row = conn.execute("SELECT COUNT(*) AS total FROM auditionees").fetchone()
        total_auditionees = row['total'] if row else 0

    return render_template('admin.html',
                           daily_password=current_pass['password'] if current_pass else None,
                           total_auditionees=total_auditionees)

@app.route('/admin/password', methods=['POST'])
@admin_required
def update_daily_password():
    new_pwd = ''.join(random.choices('0123456789ABCDEF', k=6))
    with get_db_connection() as conn:
        conn.execute("INSERT INTO daily_passwords (password) VALUES (?)", (new_pwd,))
        conn.commit()
    flash(f"New daily password generated: {new_pwd}")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reset_db', methods=['POST'])
@admin_required
def admin_reset_db():
    with get_db_connection() as conn:
        conn.execute("DELETE FROM users WHERE role='normal'")
        conn.execute("DELETE FROM auditionees")
        conn.execute("DELETE FROM assignments")
        conn.execute("DELETE FROM user_rankings")
        conn.execute("DELETE FROM votes")
        conn.commit()
    flash("Database reset complete.")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/results', methods=['POST'])
@admin_required
def view_results():
    """
    Gathers every user's ranking_data from user_rankings,
    computes an average rank for each candidate, sorts them,
    and displays the final list in a 'results.html' table.
    """
    with get_db_connection() as conn:
        rows = conn.execute("""
            SELECT user_id, ranking_data
            FROM user_rankings
        """).fetchall()

    # aggregator: candidate_positions[candidate_id] = sum of index positions
    # candidate_counts[candidate_id] = how many times candidate appeared
    candidate_positions = {}
    candidate_counts = {}

    for row in rows:
        ranking_data = json.loads(row['ranking_data'])  # e.g. [4,2,5,1,...]
        for idx, cand_id in enumerate(ranking_data):
            candidate_positions[cand_id] = candidate_positions.get(cand_id, 0) + idx
            candidate_counts[cand_id] = candidate_counts.get(cand_id, 0) + 1

    # Compute average rank
    aggregated = []
    for cand_id, total_pos in candidate_positions.items():
        avg_pos = total_pos / candidate_counts[cand_id]
        aggregated.append((cand_id, avg_pos))

    # sort by avg_pos ascending
    aggregated.sort(key=lambda x: x[1])
    aggregated.reverse()

    # Convert candidate_id => candidate_number for display
    final_list = []
    with get_db_connection() as conn:
        for cid, avg in aggregated:
            row = conn.execute("SELECT candidate_number FROM auditionees WHERE id=?", (cid,)).fetchone()
            cand_num = row['candidate_number'] if row else f"Unknown ID {cid}"
            final_list.append({
                'id': cid,
                'number': cand_num,
                'avg_pos': round(avg, 2)
            })

    return render_template('results.html', final_list=final_list)

@app.route('/admin/set_auditionees', methods=['POST'])
@admin_required
def set_auditionees():
    """
    1) Read 'candidate_count' from form.
    2) If fewer exist, auto-generate up to that count.
    3) Clear old assignments & distribute ~30% to each user.
    4) Reset user_rankings.
    """
    count_str = request.form.get('candidate_count', '0')
    try:
        desired_count = int(count_str)
    except ValueError:
        flash("Invalid number of candidates.")
        return redirect(url_for('admin_dashboard'))

    if desired_count < 1:
        flash("Candidate count must be at least 1.")
        return redirect(url_for('admin_dashboard'))

    with get_db_connection() as conn:
        # 1) Find how many auditionees currently exist
        row = conn.execute("SELECT MAX(candidate_number) AS m FROM auditionees").fetchone()
        current_max = row['m'] if row['m'] else 0

        # If current_max >= desired_count, 
        # we do NOT automatically remove extras. (You could if you want.)
        # We'll just ensure at least 'desired_count' exist by adding new
        if current_max >= desired_count:
            flash(f"There are already {current_max} auditionees, which is >= desired_count={desired_count}. No new added.")
        else:
            # 2) Generate new candidates up to desired_count
            start_num = current_max + 1
            end_num = desired_count
            for cnum in range(start_num, end_num + 1):
                conn.execute("INSERT INTO auditionees (candidate_number) VALUES (?)", (cnum,))
            flash(f"Added auditionees {start_num} through {end_num}.")

        conn.commit()

        # 3) Clear old assignments
        conn.execute("DELETE FROM assignments")

        # 4) Distribute ~30% to each user
        #    Fetch all candidate IDs
        cands = conn.execute("SELECT id FROM auditionees").fetchall()
        cand_ids = [c['id'] for c in cands]
        total_cands = len(cand_ids)

        # Fetch all normal users
        users = conn.execute("SELECT id FROM users WHERE role='normal'").fetchall()
        user_ids = [u['id'] for u in users]

        if not user_ids:
            flash("No normal users exist; skipping distribution.")
            conn.commit()
            return redirect(url_for('admin_dashboard'))

        for uid in user_ids:
            # pick 30%
            subset_size = max(1, int(0.3 * total_cands))
            chosen_candidates = random.sample(cand_ids, subset_size)
            for cid in chosen_candidates:
                conn.execute("INSERT INTO assignments (user_id, candidate_id) VALUES (?,?)",
                             (uid, cid))

        # 5) Reset or init user_rankings
        for uid in user_ids:
            assigned_count = conn.execute("""
                SELECT COUNT(*) as cnt
                FROM assignments
                WHERE user_id=?
            """, (uid,)).fetchone()['cnt']

            row = conn.execute("SELECT 1 FROM user_rankings WHERE user_id=?", (uid,)).fetchone()
            if not row:
                conn.execute("""
                    INSERT INTO user_rankings (user_id, ranking_data, comparisons_done, total_comparisons)
                    VALUES (?, ?, 0, ?)
                """, (uid, json.dumps([]), assigned_count))
            else:
                conn.execute("""
                    UPDATE user_rankings
                    SET ranking_data=?, comparisons_done=0, total_comparisons=?
                    WHERE user_id=?
                """, (json.dumps([]), assigned_count, uid))

        conn.commit()

    with get_db_connection() as conn:
        final_row = conn.execute("SELECT COUNT(*) as total FROM auditionees").fetchone()
        final_count = final_row['total']

    # Then store it in session or a global variable, or a small table that stores 'last_set_count'.
    session['last_set_auditionees'] = final_count
    flash(f"Set total auditionees to {desired_count}, actual count now {final_count}...")
    return redirect(url_for('admin_dashboard'))

###############################################################################
# REAL-TIME PROGRESS
###############################################################################
@app.route('/api/progress')
@admin_required
def api_get_progress():
    with get_db_connection() as conn:
        rows = conn.execute("""
            SELECT u.id as user_id, u.username,
                   r.comparisons_done, r.total_comparisons
            FROM users u
            LEFT JOIN user_rankings r ON u.id=r.user_id
            WHERE u.role='normal'
        """).fetchall()

    data = []
    for row in rows:
        data.append({
            'user_id': row['user_id'],
            'username': row['username'],
            'comparisons_done': row['comparisons_done'] if row['comparisons_done'] else 0,
            'total_comparisons': row['total_comparisons'] if row['total_comparisons'] else 0
        })
    return jsonify({'data': data})

@socketio.on('request_progress_update')
def handle_request_progress_update():
    with get_db_connection() as conn:
        rows = conn.execute("""
            SELECT u.id as user_id, u.username,
                   r.comparisons_done, r.total_comparisons
            FROM users u
            LEFT JOIN user_rankings r ON u.id=r.user_id
            WHERE u.role='normal'
        """).fetchall()

    data = []
    for row in rows:
        data.append({
            'user_id': row['user_id'],
            'username': row['username'],
            'comparisons_done': row['comparisons_done'] if row['comparisons_done'] else 0,
            'total_comparisons': row['total_comparisons'] if row['total_comparisons'] else 0
        })
    emit('progress_update', {'data': data})

###############################################################################
# MEMBER DASHBOARD & COMPARISON
###############################################################################
@app.route('/member_dashboard')
@login_required
def member_dashboard():
    user_id = session['user_id']
    with get_db_connection() as conn:
        user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if user['role'] == 'admin':
            return redirect(url_for('admin_dashboard'))

        assigned_count = conn.execute("""
            SELECT COUNT(*) AS cnt
            FROM assignments
            WHERE user_id=?
        """, (user_id,)).fetchone()['cnt']

        processed_count = conn.execute("""
            SELECT COUNT(*) AS cnt
            FROM assignments
            WHERE user_id=? AND processed=1
        """, (user_id,)).fetchone()['cnt']

        # Are we in the middle of inserting a candidate (multi-step)?
        inserting_cand_id = session.get('inserting_candidate_id', None)
        if not inserting_cand_id:
            # If no candidate is in insertion, we check if there's an unprocessed candidate to start
            cand_row = conn.execute("""
                SELECT ad.*
                FROM assignments a
                JOIN auditionees ad ON a.candidate_id=ad.id
                WHERE a.user_id=? AND a.processed=0
                LIMIT 1
            """, (user_id,)).fetchone()
            if cand_row:
                session['inserting_candidate_id'] = cand_row['id']
                # We'll start inserting that candidate
                # if ranking_data is empty, just place it immediately
                ranking_row = conn.execute("""
                    SELECT ranking_data
                    FROM user_rankings
                    WHERE user_id=?
                """, (user_id,)).fetchone()
                if not ranking_row:
                    # create user_rankings row if needed
                    conn.execute("""
                        INSERT INTO user_rankings (user_id, ranking_data, comparisons_done, total_comparisons)
                        VALUES (?, ?, 0, ?)
                    """, (user_id, json.dumps([]), assigned_count))
                    conn.commit()
                    ranking_data = []
                else:
                    ranking_data = json.loads(ranking_row['ranking_data'])

                if len(ranking_data) == 0:
                    # place candidate automatically
                    ranking_data.append(cand_row['id'])
                    # mark processed
                    conn.execute("""
                        UPDATE assignments
                        SET processed=1
                        WHERE user_id=? AND candidate_id=?
                    """, (user_id, cand_row['id']))
                    conn.execute("""
                        UPDATE user_rankings
                        SET ranking_data=?,
                            comparisons_done = comparisons_done + 1
                        WHERE user_id=?
                    """, (json.dumps(ranking_data), user_id))
                    conn.commit()
                    emit_progress_update(user_id)
                    flash(f"Candidate #{cand_row['candidate_number']} placed automatically (first in your list).")
                    # no session needed
                else:
                    # start a multi-step insertion
                    session['inserting_candidate_id'] = cand_row['id']
                    session['left_index'] = 0
                    session['right_index'] = len(ranking_data) - 1
                    flash(f"Starting insertion for candidate #{cand_row['candidate_number']}.")
                return redirect(url_for('member_dashboard'))

        # If we do have a candidate in session, do we compute the mid and show the comparison block?
        show_comparison = False
        candidateA = None
        candidateB = None  # the existing candidate from ranking array
        candA_videos = []
        candB_videos = []
        if inserting_cand_id:
            # We have a candidate being inserted
            # load that candidate
            cand_row = conn.execute("SELECT * FROM auditionees WHERE id=?", 
                                    (inserting_cand_id,)).fetchone()
            if cand_row:
                # find ranking_data
                ranking_row = conn.execute("""
                    SELECT ranking_data
                    FROM user_rankings
                    WHERE user_id=?
                """, (user_id,)).fetchone()
                if ranking_row:
                    ranking_data = json.loads(ranking_row['ranking_data'])
                    if 'left_index' not in session or 'right_index' not in session:
                        # That means we haven't actually set them properly, 
                        # or they got cleared. Possibly re-initialize or skip.
                        flash("No valid multi-step boundaries set. Starting fresh or no candidate.")
                        # either remove 'inserting_candidate_id' or handle differently
                        session.pop('inserting_candidate_id', None)
                        return redirect(url_for('member_dashboard'))

                    left = session['left_index']
                    right = session['right_index']
                    if left <= right:
                        mid = (left + right)//2
                        # candidate in the array
                        mid_cand_id = ranking_data[mid]
                        mid_cand = conn.execute("SELECT * FROM auditionees WHERE id=?", 
                                                (mid_cand_id,)).fetchone()
                        # we'll show the comparison
                        show_comparison = True
                        candidateA = cand_row  # the new candidate
                        candidateB = mid_cand

                        candA_videos = find_videos_for_candidate(candidateA['candidate_number'])
                        candB_videos = find_videos_for_candidate(candidateB['candidate_number'])
                    else:
                        # We found the insertion point => insert
                        insertion_pos = left
                        ranking_data.insert(insertion_pos, inserting_cand_id)
                        # mark processed in assignments
                        conn.execute("""
                            UPDATE assignments
                            SET processed=1
                            WHERE user_id=? AND candidate_id=?
                        """, (user_id, inserting_cand_id))
                        # update ranking_data in DB
                        conn.execute("""
                            UPDATE user_rankings
                            SET ranking_data=?,
                                comparisons_done = comparisons_done + 1
                            WHERE user_id=?
                        """, (json.dumps(ranking_data), user_id))
                        conn.commit()
                        emit_progress_update(user_id)
                        flash(f"Candidate #{cand_row['candidate_number']} inserted at index {insertion_pos}.")
                        # clear session so we can pick next candidate
                        session.pop('inserting_candidate_id', None)
                        session.pop('left_index', None)
                        session.pop('right_index', None)
                        return redirect(url_for('member_dashboard'))

        return render_template('dashboard.html',
                               username=user['username'],
                               assigned_count=assigned_count,
                               processed_count=processed_count,
                               show_comparison=show_comparison,
                               candidate_a=candidateA,
                               candidate_b=candidateB,
                               candA_videos=candA_videos,
                               candB_videos=candB_videos)

@app.route('/member/submit_step', methods=['POST'])
@login_required
def submit_step():
    result = request.form.get('result')
    user_id = session['user_id']

    if 'inserting_candidate_id' not in session:
        flash("No candidate currently being inserted.")
        return redirect(url_for('member_dashboard'))

    left = session['left_index']
    right = session['right_index']
    mid = (left + right) // 2
    print(f"Before: left={left}, right={right}, mid={mid}")

    if result == "a_better":
        # “Candidate A is better” => new candidate goes to a *higher index* => move left boundary up
        left = mid + 1
    elif result == "b_better":
        # “Candidate B is better” => new candidate is “lower index”
        right = mid - 1
    else:
        # tie => treat it like A is slightly better, or do something else
        # let's say “tie” => we treat it same as “a_better”:
        left = mid + 1

    print(f"After: left={left}, right={right}")

    session['left_index'] = left
    session['right_index'] = right

    return redirect(url_for('member_dashboard'))


###############################################################################
# OPTIONAL: Serve Videos from Disk (No login here)
###############################################################################
def find_videos_for_candidate(candidate_id, directory=VIDEO_DIRECTORY):
    """
    Return a list of .mp4 filenames in 'directory' that mention candidate_id 
    in the underscore portion (excluding any parentheses).
    Example: If candidate_id=2, we include '1_2_3.mp4' but exclude '3_4_5 (2).mp4'.
    """
    results = []
    candidate_str = str(candidate_id)

    for filename in os.listdir(directory):
        # Only consider .mp4 (case-insensitive)
        if not filename.lower().endswith(".mp4"):
            continue

        # Split at '(' => only consider the part before parentheses
        parts = filename.split('(', 1)
        underscore_part = parts[0].rstrip()  # e.g. "3_4_5 " or "1_2_3.mp4"

        # Remove trailing .mp4 or .mp4
        underscore_part = underscore_part.replace(".MP4", "").replace(".mp4", "").strip()

        # Extract digits from that underscore portion
        digit_list = re.findall(r'\d+', underscore_part)
        # If candidate_str is in that list, we accept
        if candidate_str in digit_list:
            results.append(filename)

    return results
###############################################################################
# UTILS
###############################################################################
@app.route('/videos/<path:filename>')
def serve_disk_video(filename):
    from flask import send_from_directory
    import os
    
    if '..' in filename or filename.startswith('/'):
        return "Invalid filename", 400
    
    full_path = os.path.join("C:\sp25 auditions", filename)
    if not os.path.exists(full_path):
        return "File not found", 404
    
    return send_from_directory("C:\sp25_auditions", filename)

@socketio.on('request_progress_update')
def handle_progress_request_socket():
    """
    Same as the route-based progress, but triggered via socket
    """
    with get_db_connection() as conn:
        rows = conn.execute("""
            SELECT u.id as user_id, u.username,
                   r.comparisons_done, r.total_comparisons
            FROM users u
            LEFT JOIN user_rankings r ON u.id=r.user_id
            WHERE u.role='normal'
        """).fetchall()

    data = []
    for row in rows:
        data.append({
            'user_id': row['user_id'],
            'username': row['username'],
            'comparisons_done': row['comparisons_done'] if row['comparisons_done'] else 0,
            'total_comparisons': row['total_comparisons'] if row['total_comparisons'] else 0
        })
    emit('progress_update', {'data': data})

###############################################################################
# MAIN
###############################################################################
if __name__ == '__main__':
    init_db()
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
