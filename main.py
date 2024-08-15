import csv
import os
import base64
import json
import argparse

from dotenv import load_dotenv
from auth0.v3.authentication import GetToken
from auth0.v3.management import Jobs, Roles

def pbkdf2string(password_hash):
    passwordhash_bytes = base64.b64decode(password_hash)
    salt_bytes = bytearray()
    pw_bytes = bytearray()

    # Break down passwordhash_string_fromdb into bytes representing salt and pw
    # The first byte represents the version of Identity being used (0 == v2.0; 1 == v3.0)
    # This script will not work if your password was not hashed using v2
    # For v2, bytes 1-17 represent the salt and bytes 18-49 represent the password
    # reference: https://github.com/aspnet/AspNetIdentity/blob/main/src/Microsoft.AspNet.Identity.Core/Crypto.cs
    if passwordhash_bytes[0] != 0:
        print('This script will not work for you because your password was hashed using something other than Identity v2')
        return
    for i in range(len(passwordhash_bytes)):
        if i > 0 and i < 17:
            salt_bytes.append(passwordhash_bytes[i])
        elif i >= 17 and i <= 49:
            pw_bytes.append(passwordhash_bytes[i])

    # Convert both back to base64 and Remove base 64 padding aka '='
    salt_b64_nopadding = base64.b64encode(salt_bytes).decode().replace('=', ' ').strip(' ')
    pw_b64_nopadding = base64.b64encode(pw_bytes).decode().replace('=', ' ').strip(' ')

    # PHC string format
    pbkdf2string = "$pbkdf2-sha1$i=1000,l=32$%s$%s" % (salt_b64_nopadding, pw_b64_nopadding)
    return pbkdf2string

def get_access_token():
    token = GetToken(os.getenv('AUTH0_DOMAIN'))
    token_response = token.client_credentials(
        os.getenv('AUTH0_CLIENT_ID'), 
        os.getenv('AUTH0_CLIENT_SECRET'), 
        os.getenv('AUTH0_AUDIENCE'))
    return token_response["access_token"]

def users():
    access_token = get_access_token()
    client = Jobs(DOMAIN, access_token)
    users = []

    with open("data/users.csv", "r") as f:
        csvreader = csv.reader(f, delimiter=";")
        for i, row in enumerate(csvreader):
            if i == 0: continue
            users.append({
                "username": row[0],
                "email": row[1],
                "custom_password_hash": {
                    "algorithm": "pbkdf2",
                    "hash": {
                        "value": pbkdf2string(row[2]),
                        "encoding": "utf8"
                    }
                }
            })

    response = client.import_users(os.getenv('AUTH0_CONNECTION_ID'), json.dumps(users))
    print(response)

def roles():
    access_token = get_access_token()
    client = Roles(DOMAIN, access_token)

    with open("data/roles.csv", "r") as f:
        csvreader = csv.reader(f, delimiter=";")
        for i, row in enumerate(csvreader):
            if i == 0: continue
            response = client.create({ "name": row[0], "description": row[1] })
            print(f"Role: {row[0]} => {response}")

def main():
    parser = argparse.ArgumentParser(description="AspNet-to-Auth0 Export")
    parser.add_argument("--users", action='store_true', help="Import users from aspnet identity")
    parser.add_argument("--roles", action='store_true', help="Import roles")
    
    args = parser.parse_args()

    if args.users:
        print("Import users started")
        users()

    if args.roles:
        print("Import roles started")
        roles()

if __name__ == "__main__":
    load_dotenv()
    main()