import requests
from abc import (ABC,
                 abstractmethod)


BASE_URL = 'http://localhost:5000/api/'

def make_get_request(url, **kwargs):
    res = requests.get(url, **kwargs)
    return res

def make_post_request(url, **kwargs):
    res = requests.post(url, **kwargs)
    return res

def make_put_request(url, **kwargs):
    res = requests.put(url, **kwargs)
    return res

def get_json_and_status_code_from_request(url, method, **kwargs):
    if method == "POST":
        response = make_post_request(url, **kwargs)
    elif method == "GET":
        response = make_get_request(url, **kwargs)
    elif method == "PUT":
        response = make_put_request(url, **kwargs)
    else:
        raise NotImplementedError
    response_json = response.json()
    status_code = response.status_code

    return response_json, status_code

class ApiTestAbstract(ABC):
    @property
    @abstractmethod
    def url(self):
        raise NotImplementedError
