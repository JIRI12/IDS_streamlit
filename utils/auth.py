import bcrypt

class Auth:
    def __init__(self, db):
        self.db = db

    def hash_password(self, password):
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed

    def check_password(self, hashed, password):
        return bcrypt.checkpw(password.encode('utf-8'), hashed)

    def login(self, username, password):
        user = self.db.get_user(username)
        if user and self.check_password(user[2], password):  # Assuming the password is the third field
            return True
        return False

    def register(self, username, password):
        if self.db.get_user(username) is None:
            hashed_password = self.hash_password(password)
            self.db.add_user(username, hashed_password)
            return True
        return False
