from flask_restful import Resource
from flask import request
from loveforpizza.utils import (HashUtils,
                                JWTUtils)
from flask_jwt_extended import (create_access_token,
                                jwt_required,
                                jwt_refresh_token_required,
                                get_jwt_identity,
                                get_raw_jwt)
from loveforpizza.parsers import (login_parser,
                                  register_parser,
                                  loves_pizza_parser,
                                  Payload)
from loveforpizza.models import (UserModel,
                                 RevokedTokenModel)
from flask import current_app

TOP_VOTERS_LIMIT = 20

class UserRegistration(Resource):
    @register_parser
    def post(self):
        payload = request.get_json(force=True)
        Payload(payload).parse()
        is_user_registered = UserModel(current_app).register({
            'username': payload['username'],
            'password': HashUtils.generate_hash(str(payload['password'])),
            'fullname': payload['fullname'],
            'love_for_pizza_count': 0
        })
        response_data = {
            "Registered": is_user_registered
        }
        if is_user_registered:
            tokens = JWTUtils.create_tokens(identity=payload['username'])
            response_data = JWTUtils.update_dict_with_tokens(response_data, tokens)
            response_data['love_for_pizza_count'] = 0
        return response_data


class UserLogin(Resource):
    @login_parser
    def post(self):
        payload = request.get_json(force=True)
        Payload(payload).parse()
        logged_in_user = UserModel(current_app).login({
            'username': payload['username'],
            'password': payload['password']
        })
        response_data = {
            "LoggedIn": logged_in_user['success']
        }
        if logged_in_user['success']:
            tokens = JWTUtils.create_tokens(identity=payload['username'])
            response_data = JWTUtils.update_dict_with_tokens(response_data, tokens)
            response_data['love_for_pizza_count'] = logged_in_user['love_for_pizza_count']
        return response_data


class UserLovesPizza(Resource):
    @jwt_required
    @loves_pizza_parser
    def put(self):
        payload = request.get_json(force=True)
        Payload(payload).parse()
        current_user = get_jwt_identity()
        if current_user != payload['username']:
            return {
                "msg": "Unauthorized"
            }, 401
        loves_pizza_success, new_count = UserModel(current_app).love_pizza(payload['username'])
        response_data = {
            "LovesPizza": loves_pizza_success
        }
        if loves_pizza_success:
            response_data.update({
                "Loves_pizza_count": new_count
            })
        return response_data


class TopVoters(Resource):
    def get(self, how_many):
        if how_many > TOP_VOTERS_LIMIT:
            return {
                    "msg": f"We are currently not supporting this request with more than {TOP_VOTERS_LIMIT} top voters"
                   }, 418
        if how_many == 0:
            return {
                       "msg": f"We are currently not supporting this request with 0 top voters"
                   }, 418
        top_voters = UserModel(current_app).get_top_voters(how_many)
        response_data = {
            "Top_Voters": top_voters
        }
        return response_data


class UserLogoutAccess(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token_success = RevokedTokenModel(current_app).revoke_token({
                "id": HashUtils.create_unique_id(),
                "jti": jti
            })
            return {"Logout": revoked_token_success}
        except Exception as e:
            raise e


class UserLogoutRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token_success = RevokedTokenModel(current_app).revoke_token({
                "id": HashUtils.create_unique_id(),
                "jti": jti
            })
            return {"Logout": revoked_token_success}
        except Exception as e:
            raise e


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = '_'+get_jwt_identity()
        access_token = create_access_token(identity=current_user)
        return {'access_token': access_token}

