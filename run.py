#!/usr/bin/python3

import argparse
import sys
from config import teams, vulnbox_net, fw_rules
from collections import namedtuple

# from .settings import Settings
# from .createVPN import teamGenerator
import wg

class Dict2Class(object): # cursed
    def __init__(self, my_dict):
        for key in my_dict:
            setattr(self, key, my_dict[key])

def main():
    parser = argparse.ArgumentParser(description='VPN configs generator for Attack Defense CTFs.')

    parser.add_argument("-l", "--host", action="store", type=str, help="Server host", required=True)
    parser.add_argument("-p", "--port", action="store", type=int, help="Start port (or one port for server)", required=True)

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-n", "--name", action="store", type=str, help="Network name")
    group.add_argument("-C", "--config", action="store_true", help="Use config.py to generate configs", default=False)
    parser.add_argument("-c", "--clients", action="store", type=int, help="Clients count (default: 5)", default=5)
    parser.add_argument("-k", "--keepalive", action="store", type=int, help="Client keepalive (default: None)", default=None)
    parser.add_argument("-o", "--output", action="store", type=str, help="Where to store configs?", default='.')
    parser.add_argument("-i", "--ip_pool_base", action="store", type=str,
                        help="Format string for ip generation (default: 10.20.{tid}.{cid})", default="10.20.{tid}.{cid}")

    # parser.add_argument("--server_config_base", action="store", type=str, help="Server base config")
    # parser.add_argument("--client_config_base", action="store", type=str, help="Client base config")
    # parser.add_argument("--client_config_part", action="store", type=str, help="Client base config part")

    # subp = parser.add_subparsers(title="iptables modules", required=False)
    parser.add_argument("-f", "--fw_rules", action='append', help=f"FW Rules, possible variants: {','.join(wg.settings.iptables_lib.keys())}")
    for name, data in wg.settings.iptables_lib.items():
        wg.settings.generate_subparser(parser, name, data["args"])

    args = parser.parse_args()

    settings = wg.settings.Settings()

    if args.clients >= 254:
        raise Exception("Too many clients")

    settings.ServerName = args.host or settings.ServerName
    settings.ClientKeepAlive = args.keepalive or settings.ClientKeepAlive
    settings.ip_pool_base = args.ip_pool_base or settings.ip_pool_base

    if args.fw_rules is not None:
        for rule_name in args.fw_rules:
            rule = wg.settings.iptables_lib[rule_name]
            pUp = rule["up"].format(n=args)
            pDown = rule["down"].format(n=args)
            settings.PostUp.append(pUp)
            settings.PostDown.append(pDown)

    elif fw_rules:
        for rule_name in fw_rules.keys():
            rule = wg.settings.iptables_lib[rule_name]
            conf_rule = Dict2Class(fw_rules[rule_name])
            pUp = rule["up"].format(n=conf_rule)
            pDown = rule["down"].format(n=conf_rule)
            settings.PostUp.append(pUp)
            settings.PostDown.append(pDown)


    print(args)
    print(settings.PostUp, settings.PostDown)
    outDir = args.output or '.'
    defaultPort = settings.StartPort

    if not args.config:
        settings.StartPort = args.port or settings.StartPort
        settings.ClientCount = args.clients or settings.ClientCount
        gen = wg.createVPN.teamGenerator(args.name, outDir, settings)
        gen.generateTeam()
    else:
        for i, team in enumerate(teams):
            settings.ClientCount = team['clients']
            settings.StartPort = (args.port or defaultPort) + i + 1
            gen = wg.createVPN.teamGenerator(team['team'], outDir, settings)
            gen.generateTeam(i+1)
        
        settings.StartPort = (args.port or defaultPort) + i + 1 + 1000
        settings.ip_pool_base = (args.ip_pool_base or settings.ip_pool_base)
        gen = wg.createVPN.teamGenerator('vulnboxes', outDir, settings)
        gen.generateVulnbox()
    # settings.server_config_base = args["server_config_base"] or settings.server_config_base
    # settings.client_config_base = args["client_config_base"] or settings.client_config_base
    # settings.client_config_part = args["client_config_part"] or settings.client_config_part


if __name__ == "__main__":
    main()
