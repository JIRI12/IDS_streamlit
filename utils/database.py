import sqlite3

class Database:
    def __init__(self):
        self.conn = sqlite3.connect('network_data.db')
        self.create_user_table()
        self.create_network_table()

    def create_user_table(self):
        with self.conn:
            self.conn.execute('''CREATE TABLE IF NOT EXISTS users (
                                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                                 username TEXT UNIQUE NOT NULL,
                                 password BLOB NOT NULL)''')

    def create_network_table(self):
        with self.conn:
            self.conn.execute('''CREATE TABLE IF NOT EXISTS network_data (
                                 id INTEGER PRIMARY KEY,
                                 ip TEXT,
                                 protocol TEXT,
                                 port INTEGER,
                                 state TEXT)''')

    def store_network_data(self, ip, protocol, port, state):
        with self.conn:
            self.conn.execute('INSERT INTO network_data (ip, protocol, port, state) VALUES (?, ?, ?, ?)',
                              (ip, protocol, port, state))

    def get_user(self, username):
        with self.conn:
            cur = self.conn.cursor()
            cur.execute('SELECT * FROM users WHERE username = ?', (username,))
            return cur.fetchone()

    def add_user(self, username, password):
        with self.conn:
            self.conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
