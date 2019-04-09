from flask import current_app
from loveforpizza.extensions import (dynamo,
                                    api,
                                    jwt,
                                    cors)
from loveforpizza.models import RevokedTokenModel

from loveforpizza.resources import (UserRegistration,
                                    UserLogin,
                                    UserLovesPizza,
                                    UserLogoutAccess,
                                    TopVoters)
def create_app():
    from flask import Flask
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object('config')
    app.config.from_pyfile('config.py')

    dynamo.init_app(app)

    api.add_resource(UserRegistration, '/api/register')
    api.add_resource(UserLogin, '/api/login')
    api.add_resource(UserLovesPizza, '/api/lovespizza')
    api.add_resource(UserLogoutAccess, '/api/logout')
    api.add_resource(TopVoters, '/api/topvoters/<int:how_many>')
    api.init_app(app)

    jwt.init_app(app)

    cors.init_app(app, origins = "http://localhost:3000", allow_headers=[
    "Content-Type", "Authorization", "Access-Control-Allow-Credentials", "Access-Control-Allow-Origin"])

    return app

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    isBlacklisted = RevokedTokenModel(current_app).is_jti_blacklisted(jti)
    return isBlacklisted

app = create_app()



