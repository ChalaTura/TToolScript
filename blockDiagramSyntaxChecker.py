import re

class Block:
    def __init__(self, name):
        self.name = name
        self.attributes = {}
        self.signals = {}

    def add_attribute(self, name, data_type):
        self.attributes[name] = data_type

    def add_signal(self, signal_name, attributes):
        self.signals[signal_name] = attributes

    def has_attribute(self, attribute):
        return attribute in self.attributes

def is_valid_block_name(name):
    return name[0].isupper() and "_" not in name

def is_valid_variable_declaration(line):
    allowed_types = ["bool", "int", "timer", "message", "key"]
    pattern = r"-\s*([a-z][a-zA-Z0-9_]*)\s*:\s*(" + "|".join(allowed_types) + ")"
    return re.match(pattern, line)

def is_valid_signal(line):
    pattern = r"~(chIn|chOut)\(([^)]+)\)"
    return re.match(pattern, line)

def validate_file(file_content):
    blocks = {}
    current_block = None
    errors = []

    for line_num, line in enumerate(file_content, 1):
        line = line.strip()
        if line and line[0].isupper():  # Start of a new block
            block_name = line.split(':')[0].strip()
            if not is_valid_block_name(block_name):
                errors.append(f"Invalid block name '{block_name}'. Block names must start with an uppercase letter and contain no spaces.")

            current_block = Block(block_name)
            blocks[block_name] = current_block

        elif line.startswith('-'):
            match = is_valid_variable_declaration(line)
            if not match:
                errors.append(f"Invalid variable declaration '{line}'. Expected format: '- variable_name: data_type', where data_type is one of bool, int, timer, message, key.")

            else:
                variable_name, data_type = match.groups()
                current_block.add_attribute(variable_name, data_type)

        elif line.startswith('~'):
            match = is_valid_signal(line)
            if not match:
                errors.append(f" Invalid signal declaration '{line}'. Expected format: '~chIn(signal_name)' or '~chOut(signal_name)'.")

            else:
                signal_type, attribute = match.groups()
                if not current_block.has_attribute(attribute):
                    errors.append(f"Signal '{signal_type}' references an undefined attribute '{attribute}' in block '{current_block.name}'.")


    return errors if errors else "File is valid."

# Example usage
filename = "abcblock.yaml" # #ouput of chatGPT
with open(filename, 'r') as file:
    file_content = file.readlines()
errors = validate_file(file_content)
if errors:
    print("Errors found:")
    for error in errors:
        print(error)
else:
    print("File is valid.")
