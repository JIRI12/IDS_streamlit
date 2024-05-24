import sqlite3

class Database:
    def __init__(self):
        self.db_path = 'network_data.db'
        self.create_user_table()
        self.create_network_table()
        
    def create_connection(self):
        return sqlite3.connect(self.db_path)    

    def create_user_table(self):
        conn = self.create_connection()
        with conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS users (
                                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                                 username TEXT UNIQUE NOT NULL,
                                 password BLOB NOT NULL,
                                 role TEXT NOT NULL CHECK(role IN ('admin', 'user')))''')

    def create_network_table(self):
        conn = self.create_connection()
        with conn:
            conn.execute ('''CREATE TABLE IF NOT EXISTS network4 (
                                 id INTEGER PRIMARY KEY,
                                 timestamp REAL DEFAULT CURRENT_TIMESTAMP,
                                 src_ip TEXT NOT NULL,
                                 dst_ip TEXT NOT NULL,
                                 protocol TEXT NOT NULL,
                                 src_port INTEGER,
                                 dst_port INTEGER,
                                 packet_size INTEGER,
                                 flags TEXT,
                                 state TEXT,
                                 payload BLOB  )''')
                                 

    def store_network_data(self, timestamp, src_ip, dst_ip , protocol, src_port,dst_port, packet_size, flags, state, payload):
        conn = self.create_connection()
        with conn:
            conn.execute('INSERT INTO network_data (ip, protocol, port, state) VALUES (?, ?, ?, ?,?,?,?,?,?,?)',
                              (timestamp, src_ip, dst_ip , protocol, src_port, dst_port,packet_size, flags, state, payload))

    def get_user(self, username):
        conn = self.create_connection()
        with conn:
            cur = conn.cursor()
            cur.execute('SELECT * FROM users WHERE username = ?', (username,))
            return cur.fetchone()

    def add_user(self, username, password, role):
        conn = self.create_connection()
        with conn:
            conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, password, role))

    def update_user_role(self, username, role):
        conn = self.create_connection()
        with conn:
            conn.execute('UPDATE users SET role = ? WHERE username = ?', (role, username))
    
    def is_users_empty(self):
        conn = self.create_connection()
        with conn:
            cur = conn.cursor()
            cur.execute('SELECT COUNT(*) FROM users')
            return cur.fetchone()[0] == 0
        
    def get_all_users(self):
        conn = self.create_connection()
        with conn:
            cur = conn.cursor()
            cur.execute('SELECT * FROM users')
            return cur.fetchall()    