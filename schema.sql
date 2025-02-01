-- schema.sql

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS daily_passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    password TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS auditionees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_number INTEGER
);

CREATE TABLE IF NOT EXISTS assignments (
    user_id INTEGER,
    candidate_id INTEGER,
    processed INTEGER DEFAULT 0,
    PRIMARY KEY (user_id, candidate_id)
);

CREATE TABLE IF NOT EXISTS user_rankings (
    user_id INTEGER PRIMARY KEY,
    ranking_data TEXT,        -- JSON array storing the user's dynamic array
    comparisons_done INTEGER DEFAULT 0,
    total_comparisons INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS votes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    voter_id INTEGER,
    candidate_a_id INTEGER,
    candidate_b_id INTEGER,
    result TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
