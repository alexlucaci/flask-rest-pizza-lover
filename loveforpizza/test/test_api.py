import pytest
from loveforpizza.parsers import (MAX_CHARS_FULL_NAME,
                                  MAX_CHARS_PASSWORD,
                                  MAX_CHARS_USERNAME)
import random
from .testutils import (BASE_URL,
                        get_json_and_status_code_from_request,
                        ApiTestAbstract)


@pytest.fixture
def register_payload():
    print("--setup--")
    username = f"testuser_{random.randint(32, 12321312)}"
    register_payload = {
        "username": username,
        "password": username,
        "fullname": f"fullname_{username}"
    }
    yield register_payload
    print("--teardown--")
    #TODO:DB CLEAN

@pytest.fixture
def login_payload():
    print("--setup--")
    login_payload = {
        "username": "test",
        "password": "test",
    }
    yield login_payload
    print("--teardown--")

@pytest.fixture
def top_voters_number():
    print("--setup--")
    top_voters_number = random.randint(1, 20)
    yield top_voters_number
    print("--teardown--")



@pytest.mark.usefixtures("register_payload", "login_payload")
class TestRegister(ApiTestAbstract):
    url = f"{BASE_URL}register"

    def test_register_success(self, register_payload):
        response_json, status_code = get_json_and_status_code_from_request(self.url,
                                                                           method="POST",
                                                                           json=register_payload)
        assert status_code == 200
        assert response_json['Registered'] == True
        assert 'access_token' in response_json
        assert 'refresh_token' in response_json

    def test_register_failed_long_password(self, register_payload):
        register_payload['password'] = register_payload['password'] + MAX_CHARS_PASSWORD*"t"
        response_json, status_code = get_json_and_status_code_from_request(self.url,
                                                                           method="POST",
                                                                           json=register_payload)
        assert status_code == 400
        assert 'access_token' not in response_json
        assert 'refresh_token' not in response_json

    def test_register_failed_long_username(self, register_payload):
        register_payload['username'] = register_payload['username'] + MAX_CHARS_USERNAME * "t"
        response_json, status_code = get_json_and_status_code_from_request(self.url,
                                                                           method="POST",
                                                                           json=register_payload)
        assert status_code == 400
        assert 'access_token' not in response_json
        assert 'refresh_token' not in response_json

    def test_register_failed_long_fullname(self, register_payload):
        register_payload['fullname'] = register_payload['fullname'] + MAX_CHARS_FULL_NAME * "t"
        response_json, status_code = get_json_and_status_code_from_request(self.url,
                                                                           method="POST",
                                                                           json=register_payload)
        assert status_code == 400
        assert 'access_token' not in response_json
        assert 'refresh_token' not in response_json

    def test_register_failed_special_chars_username(self, register_payload):
        register_payload['username'] = register_payload['username'] + '&&%$'
        response_json, status_code = get_json_and_status_code_from_request(self.url,
                                                                           method="POST",
                                                                           json=register_payload)
        assert status_code == 400
        assert 'access_token' not in response_json
        assert 'refresh_token' not in response_json

    def test_register_failed_special_chars_fullname(self, register_payload):
        register_payload['fullname'] = register_payload['fullname'] + '#$'
        response_json, status_code = get_json_and_status_code_from_request(self.url,
                                                                           method="POST",
                                                                           json=register_payload)
        assert status_code == 400
        assert 'access_token' not in response_json
        assert 'refresh_token' not in response_json

    def test_register_failed_existing_username(self, login_payload):
        login_payload['fullname'] = "test"
        response_json, status_code = get_json_and_status_code_from_request(self.url,
                                                                           method="POST",
                                                                           json=login_payload)
        assert status_code == 200
        assert response_json['Registered'] is False
        assert 'access_token' not in response_json
        assert 'refresh_token' not in response_json

@pytest.mark.usefixtures("login_payload")
class TestLogin(ApiTestAbstract):
    url = f"{BASE_URL}login"

    def test_login_success(self, login_payload):
        response_json, status_code = get_json_and_status_code_from_request(self.url,
                                                                           method="POST",
                                                                           json=login_payload)
        assert status_code == 200
        assert response_json['LoggedIn'] == True
        assert 'access_token' in response_json
        assert 'refresh_token' in response_json

    def test_login_failed_password(self, login_payload):
        login_payload['password'] = 'wrongpassword'
        response_json, status_code = get_json_and_status_code_from_request(self.url,
                                                                           method="POST",
                                                                           json=login_payload)
        assert status_code == 200
        assert response_json['LoggedIn'] == False
        assert 'access_token' not in response_json
        assert 'refresh_token' not in response_json

    def test_login_failed_username(self, login_payload):
        login_payload['username'] = 'wrongusername'
        response_json, status_code = get_json_and_status_code_from_request(self.url,
                                                                           method="POST",
                                                                           json=login_payload)
        assert status_code == 200
        assert response_json['LoggedIn'] == False
        assert 'access_token' not in response_json
        assert 'refresh_token' not in response_json

    def test_login_failed_empty_password(self, login_payload):
        login_payload['password'] = ""
        response_json, status_code = get_json_and_status_code_from_request(self.url,
                                                                           method="POST",
                                                                           json=login_payload)
        assert status_code == 400
        assert 'access_token' not in response_json
        assert 'refresh_token' not in response_json

    def test_login_failed_empty_username(self, login_payload):
        login_payload['username'] = ""
        response_json, status_code = get_json_and_status_code_from_request(self.url,
                                                                           method="POST",
                                                                           json=login_payload)
        assert status_code == 400
        assert 'access_token' not in response_json
        assert 'refresh_token' not in response_json

    def test_login_failed_empty_password_and_username(self, login_payload):
        login_payload['password'] = ""
        login_payload['username'] = ""
        response_json, status_code = get_json_and_status_code_from_request(self.url,
                                                                           method="POST",
                                                                           json=login_payload)
        assert status_code == 400
        assert 'access_token' not in response_json
        assert 'refresh_token' not in response_json

@pytest.mark.usefixtures("login_payload", "register_payload")
class TestVotePizza(ApiTestAbstract):
    url = f"{BASE_URL}lovespizza"
    login_url = f"{BASE_URL}login"
    register_url = f"{BASE_URL}register"
    logout_url = f"{BASE_URL}logout"

    def test_vote_after_login_success(self, login_payload):
        response_json, status_code = get_json_and_status_code_from_request(self.login_url,
                                                                           method="POST",
                                                                           json=login_payload)
        headers = {"Authorization": "Bearer " + response_json['access_token']}
        print(response_json)
        response_json, status_code = get_json_and_status_code_from_request(self.url,
                                                                           method="PUT",
                                                                           json={"username": login_payload["username"]},
                                                                           headers=headers)
        print(response_json)
        assert status_code == 200
        assert response_json["LovesPizza"] is True
        assert 'Loves_pizza_count' in response_json

    def test_vote_after_register_success(self, register_payload):
        response_json, status_code = get_json_and_status_code_from_request(self.register_url,
                                                                           method="POST",
                                                                           json=register_payload)
        headers = {"Authorization": "Bearer " + response_json['access_token']}
        response_json, status_code = get_json_and_status_code_from_request(self.url,
                                                                           method="PUT",
                                                                           json={"username": register_payload["username"]},
                                                                           headers=headers)
        assert status_code == 200
        assert response_json["LovesPizza"] is True
        assert 'Loves_pizza_count' in response_json

    def test_vote_unathorized_user_after_login(self, login_payload):
        response_json, status_code = get_json_and_status_code_from_request(self.login_url,
                                                                           method="POST",
                                                                           json=login_payload)
        headers = {"Authorization": "Bearer " + response_json['access_token']}
        response_json, status_code = get_json_and_status_code_from_request(self.url,
                                                                           method="PUT",
                                                                           json={"username": "dummyusername"},
                                                                           headers=headers)
        assert status_code == 401
        assert "LovesPizza" not in response_json
        assert 'Loves_pizza_count' not in response_json

    def test_vote_unathorized_user_after_register(self, register_payload):
        response_json, status_code = get_json_and_status_code_from_request(self.register_url,
                                                                           method="POST",
                                                                           json=register_payload)
        headers = {"Authorization": "Bearer " + response_json['access_token']}
        response_json, status_code = get_json_and_status_code_from_request(self.url,
                                                                           method="PUT",
                                                                           json={"username": "dummyusername2"},
                                                                           headers=headers)
        assert status_code == 401
        assert "LovesPizza" not in response_json
        assert 'Loves_pizza_count' not in response_json


    def test_vote_pizza_failed_after_login_logout(self, login_payload):
        response_json, status_code = get_json_and_status_code_from_request(self.login_url,
                                                                           method="POST",
                                                                           json=login_payload)
        headers = {"Authorization": "Bearer " + response_json['access_token']}

        get_json_and_status_code_from_request(self.logout_url,
                                              method="POST",
                                              headers=headers)
        response_json, status_code = get_json_and_status_code_from_request(self.url,
                                                                           method="PUT",
                                                                           json={"username": login_payload["username"]},
                                                                           headers=headers)
        assert status_code == 401
        assert response_json["msg"] == "Token has been revoked"
        assert 'Loves_pizza_count' not in response_json

    def test_vote_pizza_failed_after_register_logout(self, register_payload):
        response_json, status_code = get_json_and_status_code_from_request(self.register_url,
                                                                           method="POST",
                                                                           json=register_payload)
        headers = {"Authorization": "Bearer " + response_json['access_token']}

        get_json_and_status_code_from_request(self.logout_url,
                                              method="POST",
                                              headers=headers)
        response_json, status_code = get_json_and_status_code_from_request(self.url,
                                                                           method="PUT",
                                                                           json={"username": register_payload["username"]},
                                                                           headers=headers)
        assert status_code == 401
        assert response_json["msg"] == "Token has been revoked"
        assert 'Loves_pizza_count' not in response_json


@pytest.mark.usefixtures("login_payload", "register_payload")
class TestApiLogout(ApiTestAbstract):
    url = f"{BASE_URL}logout"
    login_url = f"{BASE_URL}login"
    register_url = f"{BASE_URL}register"
    def test_logout_after_login(self, login_payload):
        response_json, status_code = get_json_and_status_code_from_request(self.login_url,
                                                                           method="POST",
                                                                           json=login_payload)
        headers = {"Authorization": "Bearer " + response_json['access_token']}

        response_json, status_code = get_json_and_status_code_from_request(self.url,
                                                                           method="POST",
                                                                           headers=headers)
        assert status_code == 200
        assert response_json["Logout"] is True

    def test_logout_after_register(self, register_payload):
        response_json, status_code = get_json_and_status_code_from_request(self.register_url,
                                                                           method="POST",
                                                                           json=register_payload)
        headers = {"Authorization": "Bearer " + response_json['access_token']}

        response_json, status_code = get_json_and_status_code_from_request(self.url,
                                              method="POST",
                                              headers=headers)
        assert status_code == 200
        assert response_json["Logout"] is True


@pytest.mark.usefixtures("top_voters_number")
class TestGetTopVoters(ApiTestAbstract):
    url = f"{BASE_URL}topvoters/"

    def test_get_top_voters_number(self, top_voters_number):
        response_json, status_code = get_json_and_status_code_from_request(self.url+str(top_voters_number),
                                                                           method="GET")
        assert status_code == 200
        assert len(response_json["Top_Voters"]) == top_voters_number

    def test_get_top_voters_with_more_than_limit(self):
        top_voters_number = 30
        response_json, status_code = get_json_and_status_code_from_request(self.url+str(top_voters_number),
                                                                           method="GET")
        assert status_code == 418

    def test_get_top_voters_with_0(self):
        top_voters_number = 0
        response_json, status_code = get_json_and_status_code_from_request(self.url+str(top_voters_number),
                                                                           method="GET")
        assert status_code == 418


