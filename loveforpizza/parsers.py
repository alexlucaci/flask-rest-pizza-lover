import re
from flask_restful import reqparse, abort

MAX_CHARS_USERNAME = 20
MAX_CHARS_PASSWORD = 40
MAX_CHARS_FULL_NAME = 30


class Payload():

    def __init__(self, payload):
        self.payload = payload

    def parse(self, http_error_code=400):
        if not self._check_args_valid(self.payload):
            abort(http_error_code, message={"msg": "Invalid arguments"})


    def _check_args_valid(self, args):
        for key, value in args.items():
            if not self._check_if_empty_value(value): return False
            if not self._check_arg_length({key: value}):
                return False
            if key in ['username', 'fullname']:
                if not self._check_field_no_special_chars(value):
                    return False
        return True

    def _check_field_no_special_chars(self, field):
        regex = re.compile('[@!#$%^&*()<>?/\\}{~:]')
        if (regex.search(field) == None):
            return True
        return False

    def _check_arg_length(self, arg):
        if 'username' in arg and len(str(arg['username'])) > MAX_CHARS_USERNAME: return False
        if 'password' in arg and len(str(arg['password'])) > MAX_CHARS_PASSWORD: return False
        if 'fullname' in arg and len(str(arg['fullname'])) > MAX_CHARS_FULL_NAME: return False
        return True

    def _check_if_empty_value(self, value):
        if not value: return False
        return True

class BaseParser():
    """
    Base reqparse parser
    """
    def __init__(self):
        self.parser = reqparse.RequestParser()

    def get_parser(self):
        return self.parser

class LoginParser(BaseParser):
    """
    LoginParser with username and password as required arguments
    """
    def __init__(self):
        super().__init__()
        self.parser.add_argument('username', help='This field cannot be blank', required=True)
        self.parser.add_argument('password', help='This field cannot be blank', required=True)

class RegisterParser(LoginParser):
    """
    RegisterParser with username and password as required arguments
    """
    def __init__(self):
        super().__init__()
        self.parser.add_argument('fullname', help='This field cannot be blank', required=True)

class LovesPizzaParser(BaseParser):
    """
    LovesPizzaParser with username and password as required arguments
    """
    def __init__(self):
        super().__init__()
        self.parser.add_argument('username', help='This field cannot be blank', required=True)


def login_parser(fn):
    """
    Decorator to wrap UserLogin Resource methods
    :param fn: function to wrap
    :return: wrapped function
    """
    def wrapped(self=None):
        parser = LoginParser().get_parser()
        payload = parser.parse_args(strict=True)
        return fn(self)
    return wrapped

def register_parser(fn):
    """
    Decorator to wrap UserRegistration Resource methods
    :param fn: function to wrap
    :return: wrapped function
    """
    def wrapped(self=None):
        parser = RegisterParser().get_parser()
        payload = parser.parse_args(strict=True)
        return fn(self)
    return wrapped

def loves_pizza_parser(fn):
    """
    Decorator to wrap UserLovesPizza Resource methods
    :param fn: function to wrap
    :return: wrapped function
    """
    def wrapped(self=None):
        parser = LovesPizzaParser().get_parser()
        payload = parser.parse_args(strict=True)
        return fn(self)
    return wrapped