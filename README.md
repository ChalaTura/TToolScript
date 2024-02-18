# Syntax Validator for Blocks and State Diagrams README

## Overview
This Python toolkit provides a robust validation mechanism for block definitions and state diagrams, ensuring adherence to predefined syntax rules. It is an indispensable resource for developers, security professionals, and anyone involved in the creation or analysis of custom YAML files, state diagrams, or security protocols. Developed as a part of the Semester Project titled "Using ChatGPT as a Design Assistant for Engineers," this tool aims to automate processes within TTool ([tool.telecom-paris.fr](https://tool.telecom-paris.fr)) at EURECOM ([https://www.eurecom.fr/](https://www.eurecom.fr/)).

## Features
- **Block Validation:** Verifies the correct formatting of block names and the compliance of attributes and signals within blocks with specific rules.
- **State Diagram Validation:** Ensures the proper implementation of cryptographic and data manipulation operations, including but not limited to encryption/decryption, digital signatures, and more.
- **Detailed Error Reporting:** Delivers concise error messages detailing the nature and location of syntax errors within files.
- **Extensive Validation Range:** This toolkit is capable of validating a wide array of operations, from basic attribute and signal definitions in blocks to intricate cryptographic functions in state diagrams.

## Supported Syntax Validations
- **Block Files:** Validation covers block names, attributes, and signals.
- **State Diagrams:** Syntax validation encompasses operations such as concatenation, message retrieval, random variable generation, encryption/decryption, digital signatures, certificate handling, and message authentication codes (MAC), among others.

## Installation
The toolkit is designed to run in any standard Python environment without the need for additional installations. It utilizes Python's built-in `re` module for regex operations, simplifying the setup process.

## Contributing
We welcome contributions from the community. If you're interested in adding new features, enhancing existing validations, or fixing bugs, please fork the repository, implement your changes, and submit a pull request. Your efforts will help improve the tool's functionality and benefit users worldwide.

## Acknowledgments
A heartfelt thank you to all contributors who have offered their insights, feedback, and code improvements. Your contributions are crucial in enhancing the tool's reliability and utility for the community.
