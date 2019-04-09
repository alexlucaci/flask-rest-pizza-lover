from loveforpizza.utils import JWTUtils, HashUtils
from boto3.dynamodb.conditions import Key
from collections import defaultdict
from sortedcontainers import SortedDict
import decimal


class DynamoBaseModel():
    db_backend = 'dynamo'
    table_name = ''

    def __init__(self, current_app):
        self.connection = current_app.extensions[self.db_backend].tables[self.table_name]

    def get_item(self, **kwargs):
        return self.connection.get_item(**kwargs)

    def put_item(self, **kwargs):
        return self.connection.put_item(**kwargs)

    def update_item(self, **kwargs):
        return self.connection.update_item(**kwargs)

    def delete_item(self, **kwargs):
        return self.connection.delete_item(**kwargs)

    def query(self, **kwargs):
        return self.connection.query(**kwargs)

    def scan(self, **kwargs):
        return self.connection.scan(**kwargs)


class DomainBaseModel(DynamoBaseModel):
    def query(self, pk, sk=None, **kwargs):
        if sk:
            return super().query(KeyConditionExpression=Key(pk['key']).eq(pk['value']) &
                                     Key(sk).gte(0),
                                 **kwargs)
        return super().query(KeyConditionExpression=Key(pk['key']).eq(pk['value']), **kwargs)

    def insert_one(self, Item, key_to_check_for_duplicates=None):
        try:
            if key_to_check_for_duplicates:
                self.put_item(Item=Item, ConditionExpression=f'attribute_not_exists({key_to_check_for_duplicates})')
            else:
                self.put_item(Item=Item)
        except Exception as e:
            if 'ConditionalCheckFailedException' in str(e):
                return False
            raise
        return True

    def get_one(self, Item, **kwargs):
        return self.get_item(Key=Item, **kwargs)

    def update_one(self, **kwargs):
        return self.update_item(**kwargs)

    def delete_one(self, Item):
        self.delete_item(Key=Item)

    def get_all_items(self, return_items, **kwargs):
        return self.scan(AttributesToGet=return_items, **kwargs)

    @staticmethod
    def _check_if_query_response_has_items(response):
        if len(response['Items']) > 0:
            return True
        return False

    @staticmethod
    def _check_if_get_item_response_has_items(response):
        if 'Item' in response:
            return True
        return False

    @staticmethod
    def get_response_items_from_query(response):
        return response['Items']


class UserModel(DomainBaseModel):
    table_name = 'users'
    primary_key = 'username'

    def login(self, credentials):
        """
        :param credentials: dict; with username and password
        :return: bool; whether login was succesfull or not
        """
        response = self.query(pk={
            'key': 'username',
            'value': credentials['username']
        }, Limit=1)

        if self._check_if_query_response_has_items(response):
            if HashUtils.verify_hash(str(credentials['password']), response['Items'][0]['password']):
                return {'success': True, 'love_for_pizza_count': int(response['Items'][0]['love_for_pizza_count'])}
        return {'success': False}

    def register(self, user_information):
        """
        :param user_informations: dict wit username, password and fullname
        :return: bool; whether register was succesfull or not
        """
        return self.insert_one(Item=user_information,
                               key_to_check_for_duplicates=self.primary_key)

    def love_pizza(self, username):
        """
        :param username: string
        :return:
        """
        response = self.update_item(Key={"username": username},
            UpdateExpression= "set love_for_pizza_count = love_for_pizza_count + :val",
            ExpressionAttributeValues={":val": decimal.Decimal(1)},
            ReturnValues = "UPDATED_NEW")
        '''
        response = self.query(pk={
            'key': 'username',
            'value': username
        }, sk=self.sort_key, Limit=1)
        if not self._check_if_query_response_has_items(response):
            return False, False

        response_item = self.get_response_items_from_query(response)[0]
        password = response_item['password']
        fullname = response_item['fullname']
        love_for_pizza_count = response_item['love_for_pizza_count']
        self.delete_one(Item={
            self.primary_key: username,
            self.sort_key: love_for_pizza_count
        })

        # Register user again with love_for_pizza_count incremented
        love_for_pizza_count += 1
        is_user_registered = self.register({
            'username': username,
            'password': password,
            'fullname': fullname,
            'love_for_pizza_count': love_for_pizza_count
        })'''
        if 'Attributes' in response:
            return True, int(response['Attributes']['love_for_pizza_count'])
        return False, False

    def get_top_voters(self, how_many):
        response = self.get_all_items(return_items=[self.primary_key, 'love_for_pizza_count'])
        return self._parse_voters(response, how_many)

    def _parse_voters(self, response, how_many):
        top_voters = []
        voters_dict = defaultdict(list)
        if self._check_if_query_response_has_items(response):
            for item in response['Items']:
                voters_dict[item['love_for_pizza_count']].append(item)
        sorted_voters_dict = SortedDict(voters_dict)
        for key, list_value in sorted_voters_dict.items():
            for item in list_value:
                item['love_for_pizza_count'] = int(item['love_for_pizza_count'])
                top_voters.append(item)
        top_voters = top_voters[-how_many:][::-1]

        return top_voters




class RevokedTokenModel(DomainBaseModel):
    table_name = 'revoked_tokens'
    primary_key = 'jti'

    def revoke_token(self, token_item):
        """
        :param token_item: dict; has id and token
        :return:
        """
        return self.insert_one(Item=token_item)

    def is_jti_blacklisted(self, jti):
        response = self.get_one(Item={
            "jti": jti
        })
        if self._check_if_get_item_response_has_items(response):
            return True
        return False

