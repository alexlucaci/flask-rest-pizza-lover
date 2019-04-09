import uuid
from passlib.hash import pbkdf2_sha256
from flask_jwt_extended import (create_access_token,
                                create_refresh_token)


class HashUtils():
    def __init__(self):
        pass

    @staticmethod
    def generate_hash(password):
        return pbkdf2_sha256.hash(password)

    @staticmethod
    def verify_hash(password, hash):
        return pbkdf2_sha256.verify(password, hash)

    @staticmethod
    def create_unique_id():
        return str(uuid.uuid4())

class JWTUtils():
    def __init__(self):
        pass

    @staticmethod
    def create_tokens(identity):
        access_token = create_access_token(identity=identity, expires_delta=False)
        refresh_token = create_refresh_token(identity=identity)
        return {
            'access_token': access_token,
            'refresh_token': refresh_token
        }

    @staticmethod
    def update_dict_with_tokens(initial_dict, tokens):
        initial_dict.update(tokens)
        return initial_dict

