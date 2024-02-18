import re

class StateDiagram:
    def __init__(self):
        self.rules = []

    def add_rule(self, rule):
        self.rules.append(rule)
    @staticmethod
    def validate_concatenation(line):
        # Regular expression to match the concatenation syntax
        concat_regex = re.compile(r"concat[2-4]\(\s*\w+\s*(,\s*\w+\s*)*\)")
        concat_expr_match = concat_regex.search(line)
        if not concat_expr_match:
            return "Invalid concatenation syntax."

        concat_expr = concat_expr_match.group(0)
        match = re.match(r"concat([2-4])\(([^)]+)\)", concat_expr)
        if match:
            num_args_expected = int(match.group(1))
            args = [arg.strip() for arg in match.group(2).split(',')]
            if len(args) != num_args_expected:
                return f"Concatenation error: Expected {num_args_expected} arguments, got {len(args)}."
        else:
            return "Invalid concatenation syntax."
        return None
    @staticmethod
    def validate_retrieving_messages(line):
        # Regular expression to match the retrieving messages syntax
        get_regex = re.compile(r"get[1-4]\(\s*\w+\s*,(\s*\w+\s*,)*\s*\w+\s*\)")
        get_expr_match = get_regex.search(line)
        if not get_expr_match:
            return "Invalid retrieving messages syntax."

        get_expr = get_expr_match.group(0)
        match = re.match(r"get([1-4])\(([^)]+)\)", get_expr)
        if match:
            num_args_expected = int(match.group(1)) + 1  # +1 for the variableName
            args = [arg.strip() for arg in match.group(2).split(',')]
            if len(args) != num_args_expected:
                return f"Retrieving messages error: Expected {num_args_expected} arguments, got {len(args)}."
        else:
            return "Invalid retrieving messages syntax."
        return None

    @staticmethod
    def validate_random_variable(line):
        # Regular expression for RANDOM function syntax with optional whitespace and case-insensitive
        random_regex = re.compile(r"RANDOM\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)", re.IGNORECASE)
        match = random_regex.search(line)

        if not match:
            return "Invalid syntax for RANDOM function. Expected format: RANDOM(starting_number, ending_number)."

        # Extracting numbers and comparing
        starting_number, ending_number = int(match.group(1)), int(match.group(2))
        if ending_number <= starting_number:
            return "Invalid RANDOM range. The ending number must be greater than the starting number."

        return None
    @staticmethod
    def validate_encryption_decryption(line):
        # Regular expression for symmetric and asymmetric encryption/decryption functions
        encryption_regex = re.compile(
            r"(sencrypt|sdecrypt|aencrypt|adecrypt)\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)",
            re.IGNORECASE
        )
        match = encryption_regex.search(line)

        if not match:
            return "Invalid syntax. Expected format: [s/a]encrypt(variableName, Key) or [s/a]decrypt(variableName, Key)."

        return None
    @staticmethod
    def validate_sign_function(line):
        # Regular expression for sign function
        sign_regex = re.compile(r"sign\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)", re.IGNORECASE)
        match = sign_regex.search(line)

        if not match:
            return "Invalid syntax for sign function. Expected format: sign(variableName, Key)."

        return None

    @staticmethod
    def validate_verify_sign_function(line):
        # Regular expression for verifySign function
        verify_sign_regex = re.compile(
            r"bool\s+verifySign\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\)",
            re.IGNORECASE
        )
        match = verify_sign_regex.search(line)

        if not match:
            return "Invalid syntax for verifySign function. Expected format: bool verifySign(msg1, signature, Key)."

        return None
    @staticmethod
    def validate_pk_function(line):
        pk_regex = re.compile(r"pk\s*\(\s*(\w+)\s*\)", re.IGNORECASE)
        match = pk_regex.search(line)
        if not match:
            return "Invalid syntax for pk function. Expected format: pk(Key)."
        return None

    @staticmethod
    def validate_cert_function(line):
        cert_regex = re.compile(r"cert\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)", re.IGNORECASE)
        match = cert_regex.search(line)
        if not match:
            return "Invalid syntax for cert function. Expected format: cert(Key, Message)."
        return None

    @staticmethod
    def validate_verify_cert_function(line):
        verify_cert_regex = re.compile(r"verifyCert\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)", re.IGNORECASE)
        match = verify_cert_regex.search(line)
        if not match:
            return "Invalid syntax for verifyCert function. Expected format: verifyCert(Certificate, Key)."
        return None

    @staticmethod
    def validate_getpk_function(line):
        getpk_regex = re.compile(r"getpk\s*\(\s*(\w+)\s*\)", re.IGNORECASE)
        match = getpk_regex.search(line)
        if not match:
            return "Invalid syntax for getpk function. Expected format: getpk(Certificate)."
        return None

    @staticmethod
    def validate_dh_function(line):
        dh_regex = re.compile(r"DH\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)", re.IGNORECASE)
        match = dh_regex.search(line)
        if not match:
            return "Invalid syntax for DH key exchange function. Expected format: DH>(PublicKey, PrivateKey)."
        return None
    @staticmethod
    def validate_hash_function(line):
        hash_regex = re.compile(r"hash\s*\(\s*(\w+)\s*\)", re.IGNORECASE)
        match = hash_regex.search(line)
        if not match:
            return "Invalid syntax for hash function. Expected format: hash(Message)."
        return None

    @staticmethod
    def validate_mac_function(line):
        mac_regex = re.compile(r"MAC\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)", re.IGNORECASE)
        match = mac_regex.search(line)
        if not match:
            return "Invalid syntax for MAC function. Expected format: MAC(Message, Key)."
        return None

    @staticmethod
    def validate_verify_mac_function(line):
        verify_mac_regex = re.compile(r"verifyMac\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\)", re.IGNORECASE)
        match = verify_mac_regex.search(line)
        if not match:
            return "Invalid syntax for verifyMac function. Expected format: verifyMac(Message, Key, MAC)."
        return None

    @staticmethod
    def validate_get_key_function(line):
        get_key_regex = re.compile(r"getKey\s*\(\s*(\w+)\s*\)", re.IGNORECASE)
        match = get_key_regex.search(line)
        if not match:
            return "Invalid syntax for getKey function. Expected format: getKey(Message)."
        return None


def validate_file(file_content):
    errors = []

    for line_num, line in enumerate(file_content.split('\n'), 1):
        line = line.strip()
        error = None

        if 'concat' in line:
            error = StateDiagram.validate_concatenation(line)
        elif 'get' in line:
            error = StateDiagram.validate_retrieving_messages(line)
        elif 'RANDOM'in line:
            error = StateDiagram.validate_random_variable(line)
        elif any(func in line for func in ['sencrypt', 'sdecrypt', 'aencrypt', 'adecrypt']):
            error = StateDiagram.validate_encryption_decryption(line)

        elif 'sign' in line:
            error = StateDiagram.validate_sign_function(line)
        elif 'verifySign' in line:
            error = StateDiagram.validate_verify_sign_function(line)
        elif 'pk' in line:
            error = StateDiagram.validate_pk_function(line)
        elif 'cert' in line:
            error = StateDiagram.validate_cert_function(line)
        elif 'verifyCert' in line:
            error = StateDiagram.validate_verify_cert_function(line)
        elif 'getpk' in line:
            error = StateDiagram.validate_getpk_function(line)
        elif 'DH' in line:
            error = StateDiagram.validate_dh_function(line)

        #other methods

        if error:
            errors.append(f"Line {line_num}: {error}")

    return errors if errors else ["File is valid."]



filename = "abcstate.yaml"
with open(filename, 'r') as file:
    file_content = file.read()
errors = validate_file(file_content)
if errors and errors[0] != "File is valid.":
    print("Errors found:")
    for error in errors:
        print(error)
else:
    print("File is valid.")

