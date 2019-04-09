from flask_dynamo import Dynamo
from flask_restful import Api
from flask_jwt_extended import JWTManager
from flask_cors import CORS

jwt = JWTManager()
api = Api()
dynamo = Dynamo()
cors = CORS()