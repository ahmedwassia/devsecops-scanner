"""Intentionally vulnerable sample used by scanner tests and demos."""

import os

password = "super-secret-password"
api_key = "aB3dE5fG7hJ9kL2mN4pQ"


def unsafe(query, user_input):
    eval(user_input)
    os.system("echo " + user_input)
    cursor.execute(f"SELECT * FROM users WHERE name = '{query}'")
    import requests
    requests.get("https://example.invalid", verify=False)
