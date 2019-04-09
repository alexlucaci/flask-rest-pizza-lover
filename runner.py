from flask_script import Manager
from loveforpizza import app
from auth import app as auth_app

Manager(app)
