teams = [
    {
        'team':'Highres',
        'clients': 3,
    },
    {
        'team':'DumpRats',
        'clients': 5,
    },
    {
        'team':'tester',
        'clients': 4,
    },
]
vulnbox_net = '10.80.{cid}.{tid}'
#vulnbox_net = '10.80.{tid}.{cid}'
clients_net = '10.20.{tid}.{cid}'
router_addr = '10.10.10.1/8'
fw_rules = {
    'accept_io_ip': {
        'fw_input_ip_ip':'10.20.0.0/16',
        'fw_output_ip_ip':'10.80.0.0/16',
    },
    'block_io_ip': {
        'fw_input_ip_ip':'10.20.0.0/16',
        'fw_output_ip_ip':'10.20.0.0/16',
    },
}