-- schema.sql

-- USERS: Admin & normal committee members
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,             -- for admin only (hashed)
    role TEXT NOT NULL,        -- 'admin' or 'normal'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- DAILY PASSWORDS: for committee logins
CREATE TABLE IF NOT EXISTS daily_passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    password TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- AUDITIONEES: each has 2 videos
CREATE TABLE IF NOT EXISTS auditionees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_number INTEGER
);

-- USER_TREES: each user’s BST or partial ranking data
CREATE TABLE IF NOT EXISTS user_trees (
    user_id INTEGER PRIMARY KEY,
    tree_data TEXT,                  -- JSON or similar structure
    comparisons_done INTEGER DEFAULT 0,
    total_comparisons INTEGER DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

-- VOTES (optional if you also want to store pairwise comparison data)
CREATE TABLE IF NOT EXISTS votes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    voter_id INTEGER,
    candidate_a_id INTEGER,
    candidate_b_id INTEGER,
    result TEXT,  -- 'A_better', 'B_better', 'not_sure'
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(voter_id) REFERENCES users(id)
);

