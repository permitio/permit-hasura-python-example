import os
import jwt
import json
import logging
import requests
from flask import Flask, request, jsonify, make_response
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from typing import Optional
from dataclasses import dataclass, asdict
from permit.sync import Permit
from permit.enforcement.interfaces import UserInput


HASURA_URL = "https://proper-impala-51.hasura.app/v1/graphql"
HASURA_HEADERS = {"X-Hasura-Admin-Secret": "4PXJozLBLF1glLpR3BUOT14OSfimw9koeoAScKK05svKszM5h7NpEOLZ6TQW5aBd"}
JWT_SECRET = os.getenv("HASURA_GRAPHQL_JWT_SECRET", "a-very-secret-secret")

permit = Permit(
    pdp="http://localhost:7766",
    #Permit secert
    token="eyJhbGciOiJSUzI1NiIsImtpZCI6IjRjYjFhYjYyLWVhZTctNDFmZS04NWMwLTAyZjFlNjMyN2FlZCIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NDk5MjQ5MzAsImV4cCI6MTY4MTM3NDUzMCwiYXVkIjoiaHR0cHM6Ly9hcGkucGVybWl0LmlvL3YxLyIsImlzcyI6Imh0dHBzOi8vYXV0aC5wZXJtaXQuaW8vIiwic3ViIjoiMWJhM2EwYTMxMzk4NDYxNjk0Y2E2MTkxODdkNTZkODAifQ.Br_7laLVkcVCB5wDaXHoAMITSOCe-SPjm6VJD96h_cTSHCxlRD4q_DrCxS-kRN3K7mj8oYpThh7danKctAqDFaNN5nVp2_zgxxcKmgP-e_AkO3NSD4PSO4FSQVlBdZGqrfp7lt4K5ZECge2KWUIHQEtGUa8adNyI_LnE2q5X1DbKfRxS3DvaCGK_Bf_t-Xt26e_asynyuSOaveuM8i4_vJ6o9woukAa-3ZwWa4EtRlXsirvNU1xQTRghzZU8lzjll4noT8zSjDjZ6jsBBXEWCi26BoHMamqMj46rYWy5l7q3y3vL3xU1cFGeKWiXi1M6c-q2X1iomrnFBmKDpPSilVVSba07o3Muh5lOvzOIgU53Xcproj2XQIY-7-N-B_6Q05pFjMvUxahaq2DOsTPQtsjkCV-x6kOGN6DoMXTWm2zBuZhrSrxDECHFhTq32FNiwe5N77AuQvJHEUH6VfpcA7LqeKqSUCNhFN_SYfAv3Rxbx7XGn630SYCO0-sgtWYy_mZH3c4KttlssHioFLDukciNvRizHKMXDvF5eeKpYd1isYnr4hVcmWK-77rTvetjkVqcogVJfSvsvbZhol2OmTuN_9FQQX4bjXc30TCtFvw0SHfY2vsVrnbCR11UxYJfxBqp55TGMz6XvvempyQj4-7p4inV8h7GXDGkT_FuWeA",
)


################
# GRAPHQL CLIENT
################

@dataclass
class Client:
    url: str
    headers: dict

    def run_query(self, query: str, variables: dict, extract=False):
        request = requests.post(
            self.url,
            headers=self.headers,
            json={"query": query, "variables": variables},
        )
        assert request.ok, f"Failed with code {request.status_code}"
        return request.json()

    find_user_by_email = lambda self, email: self.run_query(
        """
            query UserByEmail($email: String!) {
                user(where: {email: {_eq: $email}}, limit: 1) {
                    id
                    email
                    password
                }
            }
        """,
        {"email": email},
    )

    create_user = lambda self, email, password: self.run_query(
        """
            mutation CreateUser($email: String!, $password: String!) {
                insert_user_one(object: {email: $email, password: $password}) {
                    id
                    email
                    password
                }
            }
        """,
        {"email": email, "password": password},
    )

    update_password = lambda self, id, password: self.run_query(
        """
            mutation UpdatePassword($id: Int!, $password: String!) {
                update_user_by_pk(pk_columns: {id: $id}, _set: {password: $password}) {
                    password
                }
            }
        """,
        {"id": id, "password": password},
    )

    list_animals =  lambda self: self.run_query(
        """
            query MyQuery {
            user {
                animal
                email
            }
            }
        """,{}
    )  

#######
# UTILS
#######

class TokenException(Exception):
    pass


Password = PasswordHasher()
client = Client(url=HASURA_URL, headers=HASURA_HEADERS)

# ROLE LOGIC FOR DEMO PURPOSES ONLY
# NOT AT ALL SUITABLE FOR A REAL APP
def generate_token(user) -> str:
    """
    Generates a JWT compliant with the Hasura spec, given a User object with field "id"
    """
    user_roles = ["user"]
    admin_roles = ["user", "admin"]
    is_admin = user["email"] == "admin@site.com"
    payload = {
        "https://hasura.io/jwt/claims": {
            "x-hasura-allowed-roles": admin_roles if is_admin else user_roles,
            "x-hasura-default-role": "admin" if is_admin else "user",
            "x-hasura-user-id": user["id"],
        },
        "email": user["email"],
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    return token


def rehash_and_save_password_if_needed(user, plaintext_password):
    if Password.check_needs_rehash(user["password"]):
        client.update_password(user["id"], Password.hash(plaintext_password))


def get_token_from_header():
        # get the auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                raise TokenException('Bearer token malformed.')
        else:
            auth_token = ''
        if auth_token:
            return jwt.decode(auth_token, JWT_SECRET, algorithms=['HS256'])
            



#############
# DATA MODELS
#############

@dataclass
class RequestMixin:
    @classmethod
    def from_request(cls, request):
        """
        Helper method to convert an HTTP request to Dataclass Instance
        """
        values = request.get("input")
        return cls(**values)

    def to_json(self):
        return json.dumps(asdict(self))


@dataclass
class CreateUserOutput(RequestMixin):
    id: int
    email: str
    password: str


@dataclass
class JsonWebToken(RequestMixin):
    token: str


@dataclass
class AuthArgs(RequestMixin):
    email: str
    password: str


##############
# MAIN SERVICE
##############

app = Flask(__name__)

@app.route("/signup", methods=["POST"])
def signup_handler():
    args = AuthArgs.from_request(request.get_json())
    hashed_password = Password.hash(args.password)
    user_response = client.create_user(args.email, hashed_password)
    if user_response.get("errors"):
        return {"message": user_response["errors"][0]["message"]}, 400
    else:
        user = user_response["data"]["insert_user_one"]
        # Let Permit know of the new user
        # We'll use the email as our unique identifier (in Prod a UUID would be better)
        user["key"] = user["email"]
        # Assign a defult basic role
        user["roles"] = [{"role":"admin", "tenant": "default"}]
        userInput = UserInput(**user)
        # Save to permit
        permit.write(permit.api.sync_user(userInput))
        return CreateUserOutput(**user).to_json()
    

@app.route("/login", methods=["POST"])
def login_handler():
    args = AuthArgs.from_request(request.get_json())
    user_response = client.find_user_by_email(args.email)
    user = user_response["data"]["user"][0]
    try:
        Password.verify(user.get("password"), args.password)
        rehash_and_save_password_if_needed(user, args.password)
        return JsonWebToken(generate_token(user)).to_json()
    except VerifyMismatchError:
        return {"message": "Invalid credentials"}, 401


@app.route("/animals", methods=["GET"])
def list_animals():
    try:
        token = get_token_from_header()
        # We used the email as our unique identifier (in Prod a UUID would be better)
        id = token["email"]
        # enforce app-level access with Permit
        if permit.check(id, "list", "animals"):
            user_response = client.list_animals()
            return jsonify(user_response["data"]["user"])
        else:        
            return make_response(jsonify({
                'message': 'Not allowed'
            } )), 403   

    except jwt.DecodeError:
        return {"message": "Invalid token"}, 401
    except TokenException:
        responseObject = {
            'status': 'fail',
            'message': 'Bearer token malformed.'
        }
        return make_response(jsonify(responseObject)), 401     

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8080)