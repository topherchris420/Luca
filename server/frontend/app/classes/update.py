#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from app.utils import read_config
import subprocess as sp
import requests
import json
import os
import re


class Update(object):

    def __init__(self):
        self.project_url = "https://api.github.com/repos/topherchris420/Luca/tags"
        self.app_path = "/usr/share/luca"
        return None

    def check_version(self):
        """
            Check if a new version of Luca is available 
            by quering the Github api and comparing the last
            tag inside the VERSION file.
            :return: dict containing the available versions.
        """
        if read_config(("frontend", "update")):
            try:
                res = requests.get(self.project_url, timeout=10)
                res.raise_for_status()
                res = json.loads(res.content.decode("utf8"))
                if not res:
                    return {"status": False, "message": "No public releases are available for version checks."}

                with open(os.path.join(self.app_path, "VERSION")) as f:
                    cv = f.read()
                    if cv != res[0]["name"]:
                        return {"status": True,
                                "message": "A new version is available",
                                "current_version": cv,
                                "next_version": res[0]["name"]}
                    else:
                        return {"status": True,
                                "message": "This is the latest version",
                                "current_version": cv}
            except:
                return {"status": False,
                        "message": "Something went wrong (no API access nor version file)"}
        else:
            return {"status": False,
                    "message": "You don't have rights to do this operation."}

    def get_current_version(self):
        """
            Get the current version of the Luca instance
            :return: dict containing the current version or error.
        """
        if read_config(("frontend", "update")):
            try:
                with open(os.path.join(self.app_path, "VERSION")) as f:
                    return {"status": True,
                            "current_version": f.read()}
            except:
                return {"status": False,
                        "message": "Something went wrong - no version file ?"}
        else:
            return {"status": False,
                    "message": "You don't have rights to do this operation."}

    def update_instance(self):
        """
            Update the instance by executing the update script.
            :return: dict containing the update status.
        """
        if read_config(("frontend", "update")):
            try:
                os.chdir(self.app_path)
                sp.Popen(["bash", os.path.join(self.app_path, "update.sh")])
                return {"status": True,
                        "message": "Luca update process started (requires repository access)"}
            except:
                return {"status": False,
                        "message": "Issue during the update"}
        else:
            return {"status": False,
                    "message": "You don't have rights to do this operation."}
