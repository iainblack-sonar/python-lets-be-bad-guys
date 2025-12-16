import base64
import mimetypes
import os
import pickle
import subprocess

from django.urls import reverse
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt


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


