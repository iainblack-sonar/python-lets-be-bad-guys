"""
Utility module with intentional code quality issues for SonarQube demonstration.
"""
import hashlib
import os
import random
import socket
import sqlite3
import ssl
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from ftplib import FTP


# SECURITY ISSUE: Hardcoded credentials
FTP_HOST = 'ftp.example.com'
FTP_USER = 'anonymous'
FTP_PASSWORD = 'guest@example.com'

SMTP_PASSWORD = 'email_password_123'
REDIS_AUTH = 'redis_secret_token'


class InsecureConnection:
    """Class demonstrating insecure network practices."""
    
    def connect_without_verification(self, host, port=443):
        """SECURITY: SSL certificate verification disabled (CWE-295)."""
        # VULNERABLE: Disabling SSL verification allows MITM attacks
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = context.wrap_socket(sock, server_hostname=host)
        ssl_sock.connect((host, port))
        return ssl_sock
    
    def connect_ftp_plaintext(self):
        """SECURITY: Plaintext FTP credentials (CWE-319)."""
        # VULNERABLE: FTP sends credentials in plaintext
        ftp = FTP(FTP_HOST)
        ftp.login(FTP_USER, FTP_PASSWORD)
        return ftp


class DatabaseHelper:
    """Database helper with SQL injection vulnerabilities."""
    
    def __init__(self, db_path='app.db'):
        self.conn = sqlite3.connect(db_path)
    
    def find_user_unsafe(self, username):
        """SECURITY: SQL Injection vulnerability (CWE-89)."""
        # VULNERABLE: String formatting in SQL query
        query = "SELECT * FROM users WHERE username = '%s'" % username
        cursor = self.conn.cursor()
        cursor.execute(query)
        return cursor.fetchall()
    
    def delete_records_unsafe(self, table, condition):
        """SECURITY: SQL Injection in DELETE statement."""
        # VULNERABLE: User input directly in SQL
        query = f"DELETE FROM {table} WHERE {condition}"
        self.conn.execute(query)
        self.conn.commit()
    
    def search_products(self, search_term):
        """SECURITY: SQL Injection with LIKE clause."""
        # VULNERABLE: Unescaped user input
        query = "SELECT * FROM products WHERE name LIKE '%" + search_term + "%'"
        return self.conn.execute(query).fetchall()


class FileProcessor:
    """File processing with multiple vulnerabilities."""
    
    def read_file_unsafe(self, user_path):
        """SECURITY: Path traversal vulnerability (CWE-22)."""
        # VULNERABLE: No path validation
        base_dir = '/var/app/data'
        full_path = base_dir + '/' + user_path
        
        with open(full_path, 'r') as f:
            return f.read()
    
    def execute_command(self, user_input):
        """SECURITY: Command injection (CWE-78)."""
        # VULNERABLE: Shell injection via user input
        cmd = 'grep -r "%s" /var/log/' % user_input
        return subprocess.check_output(cmd, shell=True)
    
    def process_xml_unsafe(self, xml_string):
        """SECURITY: XML External Entity (XXE) injection (CWE-611)."""
        # VULNERABLE: External entities not disabled
        return ET.fromstring(xml_string)
    
    def create_temp_file(self, content):
        """SECURITY: Insecure temp file with predictable name."""
        # VULNERABLE: Predictable filename, race condition
        tmp_file = '/tmp/app_temp_' + str(os.getpid())
        with open(tmp_file, 'w') as f:
            f.write(content)
        return tmp_file


class CryptoHelper:
    """Cryptography helper with weak implementations."""
    
    def hash_password_md5(self, password):
        """SECURITY: Weak password hashing (CWE-328)."""
        # VULNERABLE: MD5 is broken for password hashing
        return hashlib.md5(password.encode()).hexdigest()
    
    def hash_password_sha1(self, password):
        """SECURITY: SHA1 is also weak for passwords."""
        # VULNERABLE: SHA1 should not be used for passwords
        return hashlib.sha1(password.encode()).hexdigest()
    
    def generate_token(self, length=16):
        """SECURITY: Insecure random for security tokens (CWE-330)."""
        # VULNERABLE: random module is predictable
        chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
        return ''.join(random.choice(chars) for _ in range(length))
    
    def generate_session_id(self):
        """SECURITY: Predictable session ID generation."""
        # VULNERABLE: Based on time and PID, easily guessable
        return hashlib.md5(f'{time.time()}{os.getpid()}'.encode()).hexdigest()


# CODE QUALITY: Unused imports at module level
# (sys, time are imported but usage is minimal/questionable)


# CODE QUALITY: Global mutable state
GLOBAL_CACHE = {}
GLOBAL_COUNTER = 0


def increment_counter():
    """CODE QUALITY: Modifying global state."""
    global GLOBAL_COUNTER
    GLOBAL_COUNTER += 1
    return GLOBAL_COUNTER


def deeply_nested_function(data):
    """CODE QUALITY: Excessive nesting / high cyclomatic complexity."""
    result = []
    if data is not None:
        if isinstance(data, dict):
            for key, value in data.items():
                if key is not None:
                    if value is not None:
                        if isinstance(value, list):
                            for item in value:
                                if item is not None:
                                    if isinstance(item, str):
                                        if len(item) > 0:
                                            if item[0].isupper():
                                                result.append(item.lower())
                                            else:
                                                result.append(item.upper())
    return result


def function_too_long():
    """CODE QUALITY: Function is way too long."""
    # This function does too many things
    
    # Step 1: Initialize
    data = []
    config = {}
    status = 'pending'
    
    # Step 2: Load configuration
    config['timeout'] = 30
    config['retries'] = 3
    config['debug'] = True
    config['verbose'] = False
    config['max_items'] = 100
    config['min_items'] = 1
    config['buffer_size'] = 1024
    config['encoding'] = 'utf-8'
    
    # Step 3: Process data
    for i in range(10):
        item = {'id': i, 'value': i * 2}
        data.append(item)
    
    # Step 4: Validate
    valid_items = []
    for item in data:
        if item['id'] >= 0:
            if item['value'] >= 0:
                valid_items.append(item)
    
    # Step 5: Transform
    transformed = []
    for item in valid_items:
        new_item = {
            'identifier': item['id'],
            'amount': item['value'],
            'processed': True
        }
        transformed.append(new_item)
    
    # Step 6: Aggregate
    total = 0
    for item in transformed:
        total += item['amount']
    
    # Step 7: Format output
    output = {
        'items': transformed,
        'total': total,
        'count': len(transformed),
        'status': status,
        'config': config
    }
    
    # Step 8: Cleanup (not really needed but adds length)
    data = None
    config = None
    valid_items = None
    transformed = None
    
    return output


def duplicate_code_block_1(items):
    """CODE QUALITY: Duplicated code (copy 1)."""
    result = []
    for item in items:
        if item is not None:
            processed = item.strip().lower()
            if len(processed) > 0:
                if processed not in result:
                    result.append(processed)
    return sorted(result)


def duplicate_code_block_2(items):
    """CODE QUALITY: Duplicated code (copy 2)."""
    result = []
    for item in items:
        if item is not None:
            processed = item.strip().lower()
            if len(processed) > 0:
                if processed not in result:
                    result.append(processed)
    return sorted(result)


def duplicate_code_block_3(items):
    """CODE QUALITY: Duplicated code (copy 3)."""
    result = []
    for item in items:
        if item is not None:
            processed = item.strip().lower()
            if len(processed) > 0:
                if processed not in result:
                    result.append(processed)
    return sorted(result)


def empty_except_handler(data):
    """CODE QUALITY: Empty except block swallows errors."""
    try:
        return int(data)
    except:
        pass  # ISSUE: Silently ignoring all exceptions
    return None


def broad_exception_handler(data):
    """CODE QUALITY: Catching too broad exception."""
    try:
        result = process_data(data)
        return result
    except Exception:  # ISSUE: Should catch specific exceptions
        return None


def process_data(data):
    """Helper function for broad_exception_handler."""
    return str(data).upper()


def unused_parameter(used, unused_param):
    """CODE QUALITY: Unused function parameter."""
    # unused_param is never used
    return used * 2


def dead_code_after_return():
    """CODE QUALITY: Dead code after return statement."""
    return "done"
    # ISSUE: Unreachable code
    print("This never executes")
    cleanup()


def cleanup():
    """Helper function called from dead code."""
    pass


def comparison_issues(value):
    """CODE QUALITY: Various comparison anti-patterns."""
    # ISSUE: Use 'is' for None comparison
    if value == None:
        return "none"
    
    # ISSUE: Use 'is' for True/False comparison
    if value == True:
        return "true"
    
    if value == False:
        return "false"
    
    # ISSUE: Redundant comparison
    if value == value:
        return str(value)
    
    return "other"


def mutable_default_arg(items=[]):
    """CODE QUALITY: Mutable default argument."""
    # ISSUE: Default mutable argument - classic Python gotcha
    items.append(1)
    return items


def string_concat_loop(items):
    """CODE QUALITY: Inefficient string concatenation in loop."""
    result = ""
    for item in items:
        result = result + str(item) + ", "  # ISSUE: O(n²) complexity
    return result


class TooManyMethods:
    """CODE QUALITY: Class with too many methods (god class)."""
    
    def method_1(self): pass
    def method_2(self): pass
    def method_3(self): pass
    def method_4(self): pass
    def method_5(self): pass
    def method_6(self): pass
    def method_7(self): pass
    def method_8(self): pass
    def method_9(self): pass
    def method_10(self): pass
    def method_11(self): pass
    def method_12(self): pass
    def method_13(self): pass
    def method_14(self): pass
    def method_15(self): pass
    def method_16(self): pass
    def method_17(self): pass
    def method_18(self): pass
    def method_19(self): pass
    def method_20(self): pass


# SECURITY: Assert statements in production code (CWE-617)
def validate_with_assert(user_id):
    """SECURITY: Using assert for validation - can be disabled with -O."""
    # VULNERABLE: assert is stripped in optimized mode
    assert user_id is not None, "User ID required"
    assert isinstance(user_id, int), "User ID must be integer"
    assert user_id > 0, "User ID must be positive"
    return user_id


# SECURITY: Storing sensitive data in exception message
def login_user(username, password):
    """SECURITY: Sensitive data in exception (CWE-209)."""
    if not authenticate(username, password):
        # VULNERABLE: Password exposed in error message
        raise ValueError(f"Login failed for {username} with password {password}")
    return True


def authenticate(username, password):
    """Stub authentication function."""
    return False

