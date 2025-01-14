import os
import sys
import subprocess

from os.path import join as pjoin
from typing import List, Tuple

from .settings import Settings


class teamGenerator(object):
    name: str
    settings: Settings

    basepath: str
    epath: str
    cliexppath: str

    def __init__(self, name: str = None, base_path: str = ".", settings: Settings = Settings()):
        self.name = name or "unnamed"
        self.settings = settings

        self.basepath = pjoin(base_path, f"net_{self.name}")

        self.epath = pjoin(self.basepath, "keys")
        self.cliexppath = pjoin(self.basepath, f"net_{self.name}_conf")

        os.makedirs(self.epath, exist_ok=True)
        os.makedirs(self.cliexppath)

    def generateTeam(self, team_idx):
        server = self.generate_key(self.epath, "server")
        env = {
            "name": self.name,

            "server_ip": self.settings.ServerName,
            "port": self.settings.StartPort,

            "subnet": self.settings.ip_pool_base.format(tid=team_idx, cid=0) + "/24" + ',' + self.settings.ip_pool_vulnbox.format(tid=0, cid=0) + "/16",  # 0 and 1 reserved

            "server_private_key": server[0],
            "server_public_key": server[1],

            "server_internal_addr": self.settings.ip_pool_base.format(tid=team_idx, cid=1) + "/24",

            "client_keep_alive": (f'PersistentKeepalive = {self.settings.ClientKeepAlive}' if self.settings.ClientKeepAlive else ''),

            "server_post_up": "; ".join(self.settings.PostUp),
            "server_post_down": "; ".join(self.settings.PostDown),
            "client_post_up": f"route add -net {self.settings.ip_pool_vulnbox.format(tid=0, cid=0)}/16 gw {self.settings.ip_pool_base.format(tid=team_idx, cid=1)} ; ping -c1 {self.settings.ip_pool_base.format(tid=team_idx, cid=1)}",
            "client_post_down": f"route delete -net {self.settings.ip_pool_vulnbox.format(tid=0, cid=0)}/16 gw {self.settings.ip_pool_base.format(tid=team_idx, cid=1)}",
        }
        client_parts = []
        for client_num in range(self.settings.ClientCount):
            client = self.generate_key(self.epath, f"clients_{self.name}_{client_num}")
            env["client_num"] = client_num
            env["client_private_key"] = client[0]
            env["client_public_key"] = client[1]
            tmp_ip = self.settings.ip_pool_base.format(tid=team_idx, cid=client_num + 2)
            env["client_ip"] = tmp_ip + "/32"  # 0 and 1 reserved
            env["client_network"] = tmp_ip + "/24"  # todo: more networks?
            client_conf_name = f"{client_num}.conf"
            client_parts.append(self.settings.client_config_part.format(**env))
            
            with open(pjoin(self.cliexppath, client_conf_name), 'w') as f:
                f.write(self.settings.client_config_base.format(**env))

        with open(pjoin(self.basepath, f"server_{self.name}.conf"), 'w') as f:
            print(env)
            f.write(self.settings.server_config_base.format(**env))
            f.write("\n\n" + "\n".join(client_parts))        

        p = subprocess.Popen("tar -cvf " + f"clients_{self.name}.tar ./*", cwd=self.cliexppath, shell=True)
        p.wait()

        
    def generateVulnbox(self, team_idx):
        server = self.generate_key(self.epath, "server_vulnboxes")
        env = {
            "name": self.name,

            "server_ip": self.settings.ServerName,
            "port": self.settings.StartPort,

            "subnet": self.settings.ip_pool_base.format(tid=0, cid=0) + "/16" + ',' + self.settings.ip_pool_vulnbox.format(tid=0, cid=0) + "/16",  # 0 and 1 reserved

            "server_private_key": server[0],
            "server_public_key": server[1],

            "server_internal_addr": self.settings.ip_pool_vulnbox.format(tid=team_idx, cid=1) + "/24",

            "client_keep_alive": (f'PersistentKeepalive = {self.settings.ClientKeepAlive}' if self.settings.ClientKeepAlive else ''),

            "server_post_up": "; ".join(self.settings.PostUp),
            "server_post_down": "; ".join(self.settings.PostDown),
            "client_post_up": f"route add -net {self.settings.ip_pool_base.format(tid=0, cid=0)}/16 gw {self.settings.ip_pool_vulnbox.format(tid=team_idx, cid=1)} ; ping -c1 {self.settings.ip_pool_base.format(tid=team_idx, cid=1)}",
            "client_post_down": f"route delete -net {self.settings.ip_pool_base.format(tid=0, cid=0)}/16 gw {self.settings.ip_pool_vulnbox.format(tid=team_idx, cid=1)}",
        }
        client = self.generate_key(self.epath, self.name)
        env["client_num"] = team_idx
        env["client_private_key"] = client[0]
        env["client_public_key"] = client[1]
        tmp_ip = self.settings.ip_pool_vulnbox.format(tid=team_idx, cid=2)
        env["client_ip"] = tmp_ip + "/32"  # 0 and 1 reserved
        env["client_network"] = tmp_ip + "/24"  # todo: more networks?
        client_conf_name = f"{self.name}.conf"
        vulnbox_peer = self.settings.client_config_part.format(**env)
        
        with open(pjoin(self.cliexppath, client_conf_name), 'w') as f:
            f.write(self.settings.client_config_base.format(**env))

        # generate vulnbox server
        with open(pjoin(self.basepath, f"server_vuln{team_idx}.conf"), 'w') as f:
            f.write(self.settings.server_config_base.format(**env))
            f.write("\n\n" + vulnbox_peer)
        
    
    def generate_key(self, save_path: str, name: str) -> Tuple[str, str]:
        # private key gen
        _, privkey = self.wg_do(["genkey"])
        with open(pjoin(save_path, f"{name}-private.key"), 'wb') as f:
            f.write(privkey)

        # public key gen
        _, pubkey = self.wg_do(["pubkey"], input=privkey)
        with open(pjoin(save_path, f"{name}-public.key"), 'wb') as f:
            f.write(pubkey)

        return (privkey.decode().strip(), pubkey.decode().strip())

    def get_key(self, save_path: str, name: str) -> Tuple[str, str]:
        # private key read
        with open(pjoin(save_path, f"{name}-private.key"), 'rb') as f:
            privkey = f.read()

        # public key read
        with open(pjoin(save_path, f"{name}-public.key"), 'rb') as f:
            pubkey = f.read()

        return (privkey.decode().strip(), pubkey.decode().strip())

    def wg_do(self, args: List[str], input: bytes = b"", cwd: str = ".", shell: bool = False) -> Tuple[int, bytes]:
        cmdline = ["wg"]
        cmdline.extend(args)
        with subprocess.Popen(cmdline, shell=shell, stdout=subprocess.PIPE, stdin=subprocess.PIPE, cwd=cwd) as p:
            stdout = p.communicate(input=input)[0]
            return (p.wait(), stdout)


if __name__ == "__main__":
    test = teamGenerator(1)
    test.generate()
