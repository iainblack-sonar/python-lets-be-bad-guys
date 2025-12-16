import base64
import hashlib
import mimetypes
import os
import pickle
import random
import re
import subprocess
import tempfile
import urllib.request

from django.urls import reverse
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt

# SECURITY ISSUE: Hardcoded credentials (CWE-798)
DATABASE_PASSWORD = "admin123!"
API_SECRET_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MfszCzWx
-----END RSA PRIVATE KEY-----"""


## 01 - Injection Attacks

def norm(s):
    return s.strip().replace(' ', '').lower()


def sql(request):
    solution_sql = ("SELECT id from Users where first_name = ''; "
                    "DROP TABLE Users;--';")
    expected_sql = "'; DROP TABLE Users;--"

    name = request.POST['name'] if request.method == 'POST' else ''
    correct = (norm(name) == norm(expected_sql))

    return render(request, 'vulnerable/injection/sql.html',
            {'name': name, 'correct': correct, 'solution_sql': solution_sql})


def file_access(request):
    msg = request.GET.get('msg', '')
    return render(request, 'vulnerable/injection/file_access.html',
            {'msg': msg})


def user_pic(request):
    """A view that is vulnerable to malicious file access."""

    base_path = os.path.join(os.path.dirname(__file__), '../../badguys/static/images')
    filename = request.GET.get('p')

    try:
        data = open(os.path.join(base_path, filename), 'rb').read()
    except IOError:
        if filename.startswith('/'):
            msg = "That was worth trying, but won't always work."
        elif filename.startswith('..'):
            msg = "You're on the right track..."
        else:
            msg = "Keep trying..."
        return render(request, 'vulnerable/injection/file_access.html',
                {'msg': msg})

    return HttpResponse(data, content_type=mimetypes.guess_type(filename)[0])


def code_execution(request):
    data = ''
    msg = ''
    first_name = ''
    if request.method == 'POST':

        # Clear out a previous success to reset the exercise
        try:
            os.unlink('p0wned.txt')
        except:
            pass

        first_name = request.POST.get('first_name', '')

        try:
            # Decode base64 and execute - VULNERABLE to code injection
            exec(base64.b64decode(first_name))
        except:
            pass

        # Check to see if the attack was successful
        try:
            data = open('p0wned.txt').read()
        except IOError:
            data = ''

    return render(request, 'vulnerable/injection/code_execution.html',
            {'first_name': request.POST.get('first_name', ''), 'data': data})


def command_injection(request):
    """Vulnerable to OS command injection via shell=True."""
    output = ''
    hostname = request.POST.get('hostname', '')
    
    if request.method == 'POST' and hostname:
        # VULNERABLE: User input passed directly to shell command
        result = subprocess.Popen(
            'ping -c 1 ' + hostname,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = result.communicate()
        output = stdout.decode('utf-8', errors='replace') + stderr.decode('utf-8', errors='replace')
    
    return render(request, 'vulnerable/injection/command.html',
            {'hostname': hostname, 'output': output})


def insecure_deserialization(request):
    """Vulnerable to insecure deserialization via pickle."""
    result = ''
    user_data = request.POST.get('data', '')
    
    if request.method == 'POST' and user_data:
        try:
            # VULNERABLE: Deserializing untrusted user input with pickle
            decoded = base64.b64decode(user_data)
            obj = pickle.loads(decoded)
            result = str(obj)
        except Exception as e:
            result = f"Error: {str(e)}"
    
    return render(request, 'vulnerable/injection/deserialization.html',
            {'user_data': user_data, 'result': result})


## 02 - Broken Authentication & Session Management


## 03 - XSS

def xss_form(request):
    env = {'qs': request.GET.get('qs', 'hello')}
    response = render(request, 'vulnerable/xss/form.html', env)
    response.set_cookie(key='monster', value='omnomnomnomnom!')
    return response


def xss_path(request, path='default'):
    env = {'path': path}
    return render(request, 'vulnerable/xss/path.html', env)


def xss_query(request):
    env = {'qs': request.GET.get('qs', 'hello')}
    return render(request, 'vulnerable/xss/query.html', env)


## 04 - Insecure Direct Object References
users = {
    '1': {
        'name': 'Foo',
        'email': 'foo@example.com',
        'admin': False,
    },
    '2': {
        'name': 'Bar',
        'email': 'bar@example.com',
        'admin': True,
    }
}

def dor_user_profile(request, userid=None):
    env = {}
    user_data = users.get(userid)

    if request.method == 'POST':
        user_data['name'] = request.POST.get('name') or user_data['name']
        user_data['email'] = request.POST.get('email') or user_data['email']
        env['updated'] = True

    env['user_data'] = user_data
    env['user_id'] = userid
    return render(request, 'vulnerable/direct_object_references/profile.html', env)

## 05 - Security Misconfiguration

def boom(request):
    raise Exception('boom')


## 06 - Sensitive Data Exposure

def exposure_login(request):
    return redirect('exposure')


## 07 - Missing Function Level Access Control

def missing_access_control(request):
    env = {}
    if request.GET.get('action') == 'admin':
        return render(request, 'vulnerable/access_control/admin.html', env)
    return render(request, 'vulnerable/access_control/non_admin.html', env)


## 08 - CSRF

@csrf_exempt
def csrf_image(request):
    env = {'qs': request.GET.get('qs', '')}
    return render(request, 'vulnerable/csrf/image.html', env)


## 09 - Using Known Vulnerable Components
# No exercise, just discussion?


## 10 - Unvalidated Redirects & Forwards

def unvalidated_redirect(request):
    url = request.GET.get('url')
    return redirect(url)


def unvalidated_forward(request):
    forward = request.GET.get('fwd')
    function = globals().get(forward)

    if function:
        return function(request)

    env = {'fwd': forward}
    return render(request, 'vulnerable/redirects/forward_failed.html', env)

def admin(request):
    return render(request, 'vulnerable/redirects/admin.html', {})


## 11 - Code Quality Issues (Reliability & Maintainability)

def process_user_data(request):
    """Function with multiple reliability and maintainability issues."""
    
    # ISSUE: Unused variable (maintainability)
    unused_config = {'timeout': 30, 'retries': 3}
    
    # ISSUE: Magic numbers (maintainability)
    if len(request.GET.get('data', '')) > 256:
        return HttpResponse('Data too long', status=400)
    
    # ISSUE: Resource leak - file handle never closed (reliability)
    log_file = open('/tmp/app.log', 'a')
    log_file.write('Processing request\n')
    # Missing: log_file.close()
    
    result = None
    data = request.GET.get('data', '')
    
    # ISSUE: Empty except block - swallowing all exceptions (reliability)
    try:
        result = int(data) * 2
    except:
        pass
    
    return HttpResponse(f'Result: {result}')


def complex_validation(value, min_val, max_val, allow_none, allow_empty, 
                       trim_whitespace, convert_type, default_value,
                       error_message, strict_mode):
    """ISSUE: Too many parameters (maintainability) - cognitive complexity."""
    
    # ISSUE: High cyclomatic complexity / deep nesting (maintainability)
    if value is not None:
        if not allow_none:
            if isinstance(value, str):
                if trim_whitespace:
                    value = value.strip()
                if not allow_empty:
                    if len(value) == 0:
                        if strict_mode:
                            raise ValueError(error_message)
                        else:
                            return default_value
                if convert_type:
                    try:
                        value = int(value)
                        if value < min_val:
                            if strict_mode:
                                raise ValueError(error_message)
                            return min_val
                        if value > max_val:
                            if strict_mode:
                                raise ValueError(error_message)
                            return max_val
                    except ValueError:
                        return default_value
    else:
        if not allow_none:
            return default_value
    return value


def calculate_discount(price, user_type):
    """ISSUE: Duplicated code blocks (maintainability)."""
    
    # Duplicated logic block 1
    if user_type == 'premium':
        discount = price * 0.20
        final_price = price - discount
        tax = final_price * 0.08
        total = final_price + tax
        savings = discount
        message = f'Premium discount applied: ${discount:.2f}'
        return {'total': total, 'savings': savings, 'message': message}
    
    # Duplicated logic block 2 (copy-paste with minor changes)
    if user_type == 'gold':
        discount = price * 0.15
        final_price = price - discount
        tax = final_price * 0.08
        total = final_price + tax
        savings = discount
        message = f'Gold discount applied: ${discount:.2f}'
        return {'total': total, 'savings': savings, 'message': message}
    
    # Duplicated logic block 3 (copy-paste with minor changes)
    if user_type == 'silver':
        discount = price * 0.10
        final_price = price - discount
        tax = final_price * 0.08
        total = final_price + tax
        savings = discount
        message = f'Silver discount applied: ${discount:.2f}'
        return {'total': total, 'savings': savings, 'message': message}
    
    # Default case
    discount = 0
    final_price = price
    tax = final_price * 0.08
    total = final_price + tax
    return {'total': total, 'savings': 0, 'message': 'No discount'}


def unreachable_code_example(request):
    """ISSUE: Dead/unreachable code after return (reliability)."""
    data = request.GET.get('action')
    
    if data == 'process':
        return HttpResponse('Processed')
    else:
        return HttpResponse('Skipped')
    
    # ISSUE: Unreachable code - this will never execute
    cleanup_result = perform_cleanup()
    log_action('completed')
    return HttpResponse('Done')


def perform_cleanup():
    """Helper function that's called from unreachable code."""
    return True


def log_action(action):
    """Helper function that's called from unreachable code."""
    pass


def identical_branches(request):
    """ISSUE: Identical code in if/else branches (maintainability)."""
    status = request.GET.get('status')
    
    if status == 'active':
        result = {'status': 'ok', 'code': 200}
        message = 'Operation successful'
        return HttpResponse(f'{result} - {message}')
    else:
        # ISSUE: This branch is identical to the if branch
        result = {'status': 'ok', 'code': 200}
        message = 'Operation successful'
        return HttpResponse(f'{result} - {message}')


def process_order(request):
    """ISSUE: Commented-out code blocks (maintainability)."""
    order_id = request.GET.get('order_id')
    
    # ISSUE: Large blocks of commented-out code should be removed
    # def old_process_logic(order):
    #     if order.status == 'pending':
    #         order.status = 'processing'
    #         order.save()
    #         send_notification(order.user, 'Order processing')
    #         log_order_change(order, 'pending', 'processing')
    #         return True
    #     elif order.status == 'processing':
    #         order.status = 'shipped'
    #         order.save()
    #         send_notification(order.user, 'Order shipped')
    #         log_order_change(order, 'processing', 'shipped')
    #         return True
    #     return False
    
    # TODO: refactor this later
    # FIXME: this is broken
    # HACK: temporary workaround
    
    return HttpResponse(f'Order {order_id} processed')


## 12 - Additional Security Vulnerabilities

def ssrf_vulnerability(request):
    """SECURITY: Server-Side Request Forgery (SSRF) - CWE-918."""
    url = request.GET.get('url', '')
    content = ''
    
    if url:
        # VULNERABLE: Fetching arbitrary URLs provided by user
        # Can be used to access internal services, cloud metadata, etc.
        try:
            response = urllib.request.urlopen(url)
            content = response.read().decode('utf-8', errors='replace')[:1000]
        except Exception as e:
            content = f"Error: {str(e)}"
    
    return HttpResponse(f'<pre>{content}</pre>')


def weak_crypto_hash(request):
    """SECURITY: Use of weak cryptographic hash (CWE-328)."""
    password = request.POST.get('password', '')
    
    if password:
        # VULNERABLE: MD5 is cryptographically broken for password hashing
        hashed = hashlib.md5(password.encode()).hexdigest()
        
        # VULNERABLE: SHA1 is also weak for password hashing
        sha1_hash = hashlib.sha1(password.encode()).hexdigest()
        
        return HttpResponse(f'MD5: {hashed}, SHA1: {sha1_hash}')
    
    return HttpResponse('No password provided')


def insecure_random(request):
    """SECURITY: Use of insecure random for security purposes (CWE-330)."""
    
    # VULNERABLE: random module is not cryptographically secure
    # Should use secrets module for security-sensitive operations
    token = ''.join([str(random.randint(0, 9)) for _ in range(16)])
    session_id = random.getrandbits(128)
    reset_code = random.randrange(100000, 999999)
    
    return HttpResponse(f'Token: {token}, Session: {session_id}, Reset: {reset_code}')


def regex_dos(request):
    """SECURITY: Regular Expression Denial of Service (ReDoS) - CWE-1333."""
    user_input = request.GET.get('input', '')
    
    # VULNERABLE: Catastrophic backtracking pattern
    # Input like "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!" causes exponential time
    evil_pattern = re.compile(r'^(a+)+$')
    
    if evil_pattern.match(user_input):
        return HttpResponse('Matched!')
    return HttpResponse('No match')


def path_traversal_write(request):
    """SECURITY: Path Traversal vulnerability in file write (CWE-22)."""
    filename = request.POST.get('filename', 'output.txt')
    content = request.POST.get('content', '')
    
    # VULNERABLE: User-controlled filename without sanitization
    # Attacker can write to arbitrary locations: ../../../etc/cron.d/evil
    filepath = os.path.join('/tmp/uploads', filename)
    
    with open(filepath, 'w') as f:
        f.write(content)
    
    return HttpResponse(f'Written to {filepath}')


def xml_external_entity(request):
    """SECURITY: XML External Entity (XXE) injection - CWE-611."""
    from xml.etree import ElementTree as ET
    
    xml_data = request.POST.get('xml', '')
    result = ''
    
    if xml_data:
        # VULNERABLE: Parsing XML without disabling external entities
        # Attacker can read local files: <!ENTITY xxe SYSTEM "file:///etc/passwd">
        try:
            tree = ET.fromstring(xml_data)
            result = ET.tostring(tree, encoding='unicode')
        except Exception as e:
            result = f"Parse error: {str(e)}"
    
    return HttpResponse(f'<pre>{result}</pre>')


def insecure_temp_file(request):
    """SECURITY: Insecure temporary file creation (CWE-377)."""
    data = request.POST.get('data', '')
    
    # VULNERABLE: Predictable temp file name, race condition possible
    tmp_path = '/tmp/myapp_' + str(os.getpid()) + '.tmp'
    
    with open(tmp_path, 'w') as f:
        f.write(data)
    
    # Read it back
    with open(tmp_path, 'r') as f:
        content = f.read()
    
    return HttpResponse(f'Stored: {content}')


def sql_injection_raw(request):
    """SECURITY: SQL Injection via string formatting (CWE-89)."""
    from django.db import connection
    
    username = request.GET.get('username', '')
    
    # VULNERABLE: Direct string interpolation in SQL query
    # Attacker input: ' OR '1'='1' --
    query = f"SELECT * FROM auth_user WHERE username = '{username}'"
    
    with connection.cursor() as cursor:
        try:
            cursor.execute(query)
            rows = cursor.fetchall()
            return HttpResponse(f'Found {len(rows)} users')
        except Exception as e:
            return HttpResponse(f'Error: {str(e)}')


def log_injection(request):
    """SECURITY: Log injection vulnerability (CWE-117)."""
    import logging
    logger = logging.getLogger(__name__)
    
    username = request.GET.get('username', '')
    
    # VULNERABLE: User input written directly to logs without sanitization
    # Attacker can inject fake log entries: "admin\n[INFO] User admin logged in successfully"
    logger.info(f"Login attempt for user: {username}")
    
    return HttpResponse('Login attempt logged')


def eval_vulnerability(request):
    """SECURITY: Code injection via eval() - CWE-95."""
    expression = request.GET.get('expr', '1+1')
    
    # VULNERABLE: eval() on user input allows arbitrary code execution
    # Attacker input: __import__('os').system('rm -rf /')
    try:
        result = eval(expression)
        return HttpResponse(f'Result: {result}')
    except Exception as e:
        return HttpResponse(f'Error: {str(e)}')


## 13 - More Code Quality Issues

def function_with_bugs(request, data=[], config={}):
    """Multiple code quality issues in one function."""
    
    # ISSUE: Mutable default argument (common Python bug)
    data.append(request.GET.get('item', 'default'))
    config['last_access'] = 'now'
    
    # ISSUE: Comparison to None using == instead of is
    value = request.GET.get('value')
    if value == None:
        value = 'default'
    
    # ISSUE: Comparison to True/False using == instead of is
    flag = request.GET.get('flag')
    if flag == True:
        pass
    
    # ISSUE: Using type() instead of isinstance()
    if type(value) == str:
        value = value.upper()
    
    # ISSUE: Bare except clause
    try:
        result = int(value)
    except:
        result = 0
    
    return HttpResponse(f'Data: {data}, Result: {result}')


def too_many_returns(request):
    """ISSUE: Too many return statements (cognitive complexity)."""
    action = request.GET.get('action', '')
    
    if action == 'a':
        return HttpResponse('Action A')
    if action == 'b':
        return HttpResponse('Action B')
    if action == 'c':
        return HttpResponse('Action C')
    if action == 'd':
        return HttpResponse('Action D')
    if action == 'e':
        return HttpResponse('Action E')
    if action == 'f':
        return HttpResponse('Action F')
    if action == 'g':
        return HttpResponse('Action G')
    if action == 'h':
        return HttpResponse('Action H')
    return HttpResponse('Unknown action')


def unused_variables_example(request):
    """ISSUE: Multiple unused variables."""
    unused_a = 'this is never used'
    unused_b = 42
    unused_c = ['list', 'never', 'used']
    unused_d = {'dict': 'also unused'}
    
    used_value = request.GET.get('value', 'default')
    return HttpResponse(f'Value: {used_value}')


def string_concat_in_loop(request):
    """ISSUE: Inefficient string concatenation in loop."""
    result = ''
    
    # ISSUE: String concatenation in loop is O(n²)
    for i in range(100):
        result = result + f'Item {i}, '
    
    return HttpResponse(result)


def global_variable_mutation():
    """ISSUE: Modifying global state."""
    global DATABASE_PASSWORD
    # ISSUE: Mutating global variables is bad practice
    DATABASE_PASSWORD = "new_password_123"
    return DATABASE_PASSWORD

