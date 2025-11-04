import hashlib
from typing import Tuple, Optional
import sys
import requests

#Breach Checker logic
def checkBreached(password: str) -> Tuple[bool, Optional[int]]:
    """
    This function receives a password and evaluates if it's been breached by leveraging Have I Been Pwned

    Args:
        password: str

    Returns: Tuple
         a. is_pwned - bool: Shows if password has been breached or not.
         b. breach_count - int: Indicates how many times the password has been breached.
    """

    #No Password = No Breach
    if not password:
        return False, None

    #Processing Entered Password
    password_bytes = password.encode("utf-8")
    password_hash = hashlib.sha1(password_bytes).hexdigest().upper()

    #Prefix [first five chars] to send to HIBP, Suffix [the rest of the chars] to match with response suffixes
    pw_prefix, pw_suffix = password_hash[:5], password_hash[5:]

    #Attempting to Query HIBP with Password Hash Prefix
    get_request_url = f"https://api.pwnedpasswords.com/range/{pw_prefix}"

    try:
        response = requests.get(get_request_url, timeout=5)
        response.raise_for_status()
    except requests.exceptions.RequestException as error:
        print(f"Error querying HIBP: {error} .", file=sys.stderr)
        return False, None

    #split raw response from HIBP into lines and then the lines will be split by ":"
    for line in response.text.splitlines():
        response_suffix, breach_count = line.split(":")

        #If password suffix matches response suffix, password has been breached
        if response_suffix == pw_suffix:
            return True, int(breach_count)

    return False, None