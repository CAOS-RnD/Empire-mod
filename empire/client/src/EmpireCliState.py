import logging
import os
from typing import Dict, Optional

import requests
import socketio

from empire.client.src.EmpireCliConfig import empire_config
from empire.client.src.menus import Menu
from empire.client.src.MenuState import menu_state
from empire.client.src.utils import print_util

log = logging.getLogger(__name__)

try:
    from tkinter import Tk, filedialog
except ImportError:
    Tk = None
    filedialog = None
    log.error("Failed to load tkinter. Please install tkinter to use the file prompts.")
    log.error(
        "Check the wiki for more information: https://bc-security.gitbook.io/empire-wiki/quickstart/installation"
        "#modulenotfounderror-no-module-named-_tkinter"
    )
    pass


class EmpireCliState(object):
    def __init__(self):
        self.host = ""
        self.port = ""
        self.token = ""
        self.sio: Optional[socketio.Client] = None
        self.connected = False
        self.menus = []

        # These are cached values that can be used for autocompletes and other things.
        # When switching menus, refresh these cached values by calling their respective 'get' functions.
        # In the future, maybe we'll set a scheduled task to refresh this every n seconds/minutes?
        self.listeners = {}
        self.listener_types = []
        self.stagers = {}
        self.stager_types = []
        self.modules = {}
        self.active_agents = []
        self.agents = {}
        self.plugins = {}
        self.me = {}
        self.profiles = {}
        self.bypasses = {}
        self.credentials = {}
        self.empire_version = ""
        self.cached_plugin_results = {}
        self.chat_cache = []
        self.server_files = {}
        self.hide_stale_agents = False

        # { session_id: { task_id: 'output' }}
        self.cached_agent_results = {}

        # directories for download/upload files
        self.directory = {}

        # install path for client
        self.install_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

    def register_menu(self, menu: Menu):
        self.menus.append(menu)

    def notify_connected(self):
        log.debug("Calling connection handlers.")
        for menu in self.menus:
            menu.on_connect()

    def notify_disconnected(self):
        for menu in self.menus:
            menu.on_disconnect()

    def connect(self, host, port, socketport, username, password):
        self.host = host
        self.port = port
        server = f"{host}:{port}"

        try:
            response = requests.post(
                url=f"{server}/token",
                data={"username": username, "password": password},
                verify=False,
            )
        except Exception as e:
            return e

        if response.status_code == 200:
            self.token = response.json()["access_token"]
            self.connected = True

            self.sio = socketio.Client(ssl_verify=False, reconnection_attempts=3)
            self.sio.connect(f"{server}/socket.io/", auth={"token": self.token})

            # Wait for version to be returned
            self.empire_version = self.get_version()["version"]

            self.init()
            self.init_handlers()
            self.notify_connected()
            print_util.title(
                self.empire_version,
                server,
                len(self.modules),
                len(self.listeners),
                len(self.active_agents),
            )
            return response

        elif response.status_code == 401:
            return response

    def init(self):
        self.get_listeners()
        self.get_listener_types()
        self.get_stagers()
        self.get_modules()
        self.get_agents()
        self.get_active_plugins()
        self.get_user_me()
        self.get_malleable_profile()
        self.get_bypasses()
        self.get_credentials()
        self.get_files()
        self.get_directories()

    def init_handlers(self):
        if self.sio:
            self.sio.on(
                "listeners/new",
                lambda data: [
                    print(
                        print_util.color(
                            "[+] Listener " + data["name"] + " successfully started"
                        )
                    ),
                    self.get_listeners(),
                ],
            )
            self.sio.on(
                "agents/new",
                lambda data: [
                    print(
                        print_util.color(
                            "[+] New agent " + data["name"] + " checked in"
                        )
                    ),
                    self.get_agents(),
                ],
            )

            # Multiple checkin messages or a single one?
            self.sio.on(
                "agents/stage2",
                lambda data: print(
                    print_util.color(
                        "[*] Sending agent (stage 2) to "
                        + data["name"]
                        + " at "
                        + data["external_ip"]
                    )
                ),
            )

            # Todo: need to only display results from the current agent and user. Otherwise there will be too many
            #  returns when you add more users self.sio.on('agents/task', lambda data: print(data['data']))

    def disconnect(self):
        self.host = ""
        self.port = ""
        self.token = ""
        self.connected = False
        self.notify_disconnected()

        if self.sio:
            self.sio.disconnect()

    def shutdown(self):
        self.disconnect()

    def add_to_cached_results(self, data) -> None:
        """
        When tasking results come back, we will display them if the current menu is the InteractMenu.
        Otherwise, we will add them to the agent result dictionary and display them when the InteractMenu
        is loaded.
        :param data: the tasking object
        :return:
        """
        session_id = data["agent_id"]
        if not self.cached_agent_results.get(session_id):
            self.cached_agent_results[session_id] = {}

        if isinstance(data["output"], bytes):
            data["output"] = data["output"].decode("UTF-8")

        if (
            menu_state.current_menu_name == "InteractMenu"
            and menu_state.current_menu.selected == session_id
        ):
            if data["output"] is not None:
                print(
                    print_util.color(
                        "[*] Task " + str(data["id"]) + " results received"
                    )
                )
                for line in data["output"].split("\n"):
                    print(print_util.color(line))
        else:
            self.cached_agent_results[session_id][data["id"]] = data["output"]

    def add_plugin_cache(self, data) -> None:
        """
        When plugin results come back, we will display them if the current menu is for the plugin.
        Otherwise, we will ad them to the plugin result dictionary and display them when the plugin menu
        is loaded.
        :param data: the plugin object
        :return:
        """
        plugin_name = data["plugin_name"]
        if not self.cached_plugin_results.get(plugin_name):
            self.cached_plugin_results[plugin_name] = {}

        if (
            menu_state.current_menu_name == "UsePluginMenu"
            and menu_state.current_menu.selected == plugin_name
        ):
            if data["message"] is not None:
                print(print_util.color(data["message"]))
        else:
            self.cached_plugin_results[plugin_name][data["message"]] = data["message"]

    def bottom_toolbar(self):
        if self.connected:
            agent_tasks = list(self.cached_agent_results.keys())
            plugin_tasks = list(self.cached_plugin_results.keys())

            toolbar_text = [("bold", "Connected: ")]
            toolbar_text.append(("bg:#FF0000 bold", f"{self.host}:{self.port} "))
            toolbar_text.append(("bold", "| "))
            toolbar_text.append(("bg:#FF0000 bold", f"{len(self.active_agents)} "))
            toolbar_text.append(("bold", "agent(s) | "))
            toolbar_text.append(("bg:#FF0000 bold", f"{len(self.chat_cache)} "))
            toolbar_text.append(("bold", "unread message(s) "))

            agent_text = ""
            for agents in agent_tasks:
                if self.cached_agent_results[agents]:
                    agent_text += f" {agents}"
            if agent_text:
                toolbar_text.append(("bold", "| Agent(s) received task results:"))
                toolbar_text.append(("bg:#FF0000 bold", f"{agent_text} "))

            plugin_text = ""
            for plugins in plugin_tasks:
                if self.cached_plugin_results[plugins]:
                    plugin_text += f" {plugins}"
            if plugin_text:
                toolbar_text.append(("bold", "| Plugin(s) received task result(s):"))
                toolbar_text.append(("bg:#FF0000 bold", f"{plugin_text} "))

            return toolbar_text

        else:
            return ""

    def search_files(self):
        """
        Find a file and return filename.
        """
        if filedialog and Tk:
            tk = Tk()
            tk.withdraw()
            file_directory = filedialog.askopenfilename(title="Select file")
            return file_directory
        else:
            return None

    def get_directories(self):
        """
        Get download folder path from config file
        """
        directories = empire_config.yaml.get("directories", {})
        for key, value in directories.items():
            self.directory[key] = value
            if self.directory[key][-1] != "/":
                self.directory[key] += "/"

    # I think we will break out the socketio handler and http requests to new classes that the state imports.
    # This will do for this iteration.
    def get_listeners(self):
        response = requests.get(
            url=f"{self.host}:{self.port}/api/v2/listeners",
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        self.listeners = {x["name"]: x for x in response.json()["records"]}
        return self.listeners

    def upload_file(self, filename: str, file_data: bytes):
        response = requests.post(
            url=f"{self.host}:{self.port}/api/v2/downloads",
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
            data={},
            files=[("file", (filename, file_data, "application/octet-stream"))],
        )
        return response.json()

    def download_file(self, file_id: str):
        response = requests.get(
            url=f"{self.host}:{self.port}/api/v2/downloads/{file_id}",
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def get_files(self):
        response = requests.get(
            url=f"{self.host}:{self.port}/api/v2/downloads",
            verify=False,
            params={"sources": "upload"},
            headers={"Authorization": f"Bearer {self.token}"},
        )
        self.server_files = {x["filename"]: x for x in response.json()["records"]}
        return self.server_files

    def get_version(self):
        response = requests.get(
            url=f"{self.host}:{self.port}/api/v2/meta/version",
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def kill_listener(self, listener_id: str):
        response = requests.delete(
            url=f"{self.host}:{self.port}/api/v2/listeners/{listener_id}",
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        self.get_listeners()
        return response

    def edit_listener(self, listener_id: str, options: Dict):
        response = requests.put(
            url=f"{self.host}:{self.port}/api/v2/listeners/{listener_id}",
            json=options,
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def get_listener_types(self):
        response = requests.get(
            url=f"{self.host}:{self.port}/api/v2/listener-templates",
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        self.listener_types = [x["id"] for x in response.json()["records"]]
        return self.listener_types

    def get_listener_template(self, listener_id: str):
        response = requests.get(
            url=f"{self.host}:{self.port}/api/v2/listener-templates/{listener_id}",
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def get_listener_options(self, listener_type: str):
        response = requests.get(
            url=f"{self.host}:{self.port}/api/v2/listener-templates/{listener_type}",
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def create_listener(self, options: Dict):
        response = requests.post(
            url=f"{self.host}:{self.port}/api/v2/listeners",
            json=options,
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        # todo push to state array or just call get_listeners() to refresh cache??
        return response.json()

    def get_stagers(self):
        # todo need error handling in all api requests
        response = requests.get(
            url=f"{self.host}:{self.port}/api/v2/stager-templates",
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )

        self.stagers = {x["id"]: x for x in response.json()["records"]}
        return self.stagers

    def create_stager(self, options: Dict):
        response = requests.post(
            url=f"{self.host}:{self.port}/api/v2/stagers",
            json=options,
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def download_stager(self, link: str):
        response = requests.get(
            url=f"{self.host}:{self.port}{link}",
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.content

    def get_agents(self):
        response = requests.get(
            url=f"{self.host}:{self.port}/api/v2/agents",
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )

        self.agents = {x["name"]: x for x in response.json()["records"]}

        # Whenever agents are refreshed, add socketio listeners for taskings.
        for name, agent in self.agents.items():
            session_id = agent["session_id"]
            self.sio.on(f"agents/{session_id}/task", self.add_to_cached_results)

        # Get active agents
        self.active_agents = list(
            map(
                lambda a: a["name"],
                filter(lambda a: a["stale"] is not True, state.agents.values()),
            )
        )
        return self.agents

    def get_modules(self):
        response = requests.get(
            url=f"{self.host}:{self.port}/api/v2/modules",
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )

        self.modules = {x["id"]: x for x in response.json()["records"] if x["enabled"]}
        return self.modules

    def execute_module(self, session_id: str, options: Dict):
        response = requests.post(
            url=f"{self.host}:{self.port}/api/v2/agents/{session_id}/tasks/module",
            json=options,
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def update_agent(self, session_id: str, options: Dict):
        response = requests.put(
            url=f"{self.host}:{self.port}/api/v2/agents/{session_id}",
            json=options,
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def kill_agent(self, agent_name: str):
        response = requests.post(
            url=f"{self.host}:{self.port}/api/v2/agents/{agent_name}/tasks/exit",
            json={},
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response

    def create_socks(self, agent_name: str, port: int):
        response = requests.post(
            url=f"{self.host}:{self.port}/api/v2/agents/{agent_name}/tasks/socks",
            json={"port": port},
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def view_jobs(self, agent_name: str):
        response = requests.post(
            url=f"{self.host}:{self.port}/api/v2/agents/{agent_name}/tasks/jobs",
            json={},
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def kill_job(self, agent_name: str, task_id: int):
        response = requests.post(
            url=f"{self.host}:{self.port}/api/v2/agents/{agent_name}/tasks/kill_job",
            json={"id": task_id},
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def update_agent_comms(self, agent_name: str, listener_name: str):
        response = requests.post(
            url=f"{self.host}:{self.port}/api/v2/agents/{agent_name}/tasks/update_comms",
            json={"listener": listener_name},
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def update_agent_kill_date(self, agent_name: str, kill_date: str):
        response = requests.post(
            url=f"{self.host}:{self.port}/api/v2/agents/{agent_name}/tasks/kill_date",
            json={"kill_date": kill_date},
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def update_agent_proxy(self, session_id: str, options: list):
        response = requests.post(
            url=f"{self.host}:{self.port}/api/v2/agents/{session_id}/tasks/proxy_list",
            json={"proxy": options},
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        log.error("todo: fix update agent proxy")
        return response.json()

    def get_proxy_info(self, session_id: str):
        response = requests.get(
            url=f"{self.host}:{self.port}/api/v2/agents/{session_id}/tasks/proxy_list",
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        log.error("todo: fix get agent proxy")
        return response.json()

    def update_agent_working_hours(self, session_id: str, working_hours: str):
        response = requests.put(
            url=f"{self.host}:{self.port}/api/v2/agents/{session_id}/tasks/working_hours",
            json={"working_hours": working_hours},
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def agent_shell(self, session_id: str, shell_cmd: str, literal: bool = False):
        response = requests.post(
            url=f"{self.host}:{self.port}/api/v2/agents/{session_id}/tasks/shell",
            json={"command": shell_cmd, "literal": literal},
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def sysinfo(self, session_id: str):
        response = requests.post(
            url=f"{self.host}:{self.port}/api/v2/agents/{session_id}/tasks/sysinfo",
            json={},
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def agent_script_import(self, session_id: str, filename: str, file_data: bytes):
        response = requests.post(
            url=f"{self.host}:{self.port}/api/v2/agents/{session_id}/tasks/script_import",
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
            data={},
            files=[("file", (filename, file_data, "application/octet-stream"))],
        )
        return response.json()

    def agent_script_command(self, session_id: str, script_command: str):
        response = requests.post(
            url=f"{self.host}:{self.port}/api/v2/agents/{session_id}/tasks/script_command",
            json={"command": script_command},
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def scrape_directory(self, session_id: str):
        response = requests.post(
            url=f"{self.host}:{self.port}/api/v2/agents/{session_id}/tasks/directory",
            json={"path": "/"},
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def get_agent_tasks(self, agent_name, num_results):
        response = requests.get(
            url=f"{self.host}:{self.port}/api/v2/agents/{agent_name}/tasks",
            verify=False,
            params={"limit": num_results, "order_direction": "desc", "order_by": "id"},
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def get_agent_task(self, agent_name, task_id):
        response = requests.get(
            url=f"{self.host}:{self.port}/api/v2/agents/{agent_name}/tasks/{task_id}",
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def get_credentials(self):
        response = requests.get(
            url=f"{self.host}:{self.port}/api/v2/credentials",
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        self.credentials = {str(x["id"]): x for x in response.json()["records"]}
        return self.credentials

    def get_credential(self, cred_id):
        response = requests.get(
            url=f"{self.host}:{self.port}/api/v2/credentials/{cred_id}",
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def edit_credential(self, cred_id, cred_options: Dict):
        response = requests.put(
            url=f"{self.host}:{self.port}/api/v2/credentials/{cred_id}",
            verify=False,
            json=cred_options,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def add_credential(self, cred_options):
        response = requests.post(
            url=f"{self.host}:{self.port}/api/v2/credentials",
            json=cred_options,
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def remove_credential(self, cred_id):
        response = requests.delete(
            url=f"{self.host}:{self.port}/api/v2/credentials/{cred_id}",
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response

    def get_active_plugins(self):
        response = requests.get(
            url=f"{self.host}:{self.port}/api/v2/plugins",
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )

        self.plugins = {x["name"]: x for x in response.json()["records"]}
        for name, plugin in self.plugins.items():
            plugin_name = plugin["name"]
            self.sio.on(f"plugins/{plugin_name}/notifications", self.add_plugin_cache)
        return self.plugins

    def get_plugin(self, plugin_name):
        response = requests.get(
            url=f"{self.host}:{self.port}/api/v2/plugins/{plugin_name}",
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def execute_plugin(self, uid: str, options: Dict):
        response = requests.post(
            url=f"{self.host}:{self.port}/api/v2/plugins/{uid}/execute",
            json=options,
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def agent_upload_file(self, agent_name: str, file_id: int, file_path: str):
        response = requests.post(
            url=f"{self.host}:{self.port}/api/v2/agents/{agent_name}/tasks/upload",
            json={"file_id": file_id, "path_to_file": file_path},
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def agent_download_file(self, agent_name: str, file_name: str):
        response = requests.post(
            url=f"{self.host}:{self.port}/api/v2/agents/{agent_name}/tasks/download",
            json={"path_to_file": file_name},
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response

    def agent_sleep(self, agent_name: str, delay: int, jitter: float):
        response = requests.post(
            url=f"{self.host}:{self.port}/api/v2/agents/{agent_name}/tasks/sleep",
            json={"delay": delay, "jitter": jitter},
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def get_users(self):
        response = requests.get(
            url=f"{self.host}:{self.port}/api/v2/users",
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def create_user(self, new_user):
        response = requests.post(
            url=f"{self.host}:{self.port}/api/v2/users",
            json=new_user,
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def edit_user(self, user_id: str, user):
        response = requests.put(
            url=f"{self.host}:{self.port}/api/v2/users/{user_id}",
            json=user,
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def get_user(self, user_id: str):
        response = requests.get(
            url=f"{self.host}:{self.port}/api/v2/users/{user_id}",
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def get_user_me(self):
        response = requests.get(
            url=f"{self.host}:{self.port}/api/v2/users/me",
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )

        self.me = response.json()
        return response.json()

    def get_malleable_profile(self):
        response = requests.get(
            url=f"{self.host}:{self.port}/api/v2/malleable-profiles",
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )

        self.profiles = {x["name"]: x for x in response.json()["records"]}
        return self.profiles

    def get_bypasses(self):
        response = requests.get(
            url=f"{self.host}:{self.port}/api/v2/bypasses",
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )

        self.bypasses = {x["name"]: x for x in response.json()["records"]}
        return self.bypasses

    def add_malleable_profile(self, data):
        response = requests.post(
            url=f"{self.host}:{self.port}/api/v2/malleable-profiles",
            json=data,
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def delete_malleable_profile(self, profile_id: str):
        response = requests.delete(
            url=f"{self.host}:{self.port}/api/v2/malleable-profiles/{profile_id}",
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response.json()

    def preobfuscate(self, language: str, reobfuscate: bool):
        response = requests.post(
            url=f"{self.host}:{self.port}/api/v2/obfuscation/global/{language}/preobfuscate?reobfuscate={reobfuscate}",
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response

    def keyword_obfuscation(self, options: dict):
        response = requests.post(
            url=f"{self.host}:{self.port}/api/v2/obfuscation/keywords",
            json=options,
            verify=False,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        return response


state = EmpireCliState()
