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
        'ip_pool_base': '10.20.13.{cid}',
    },
]
vulnbox_net = '10.80.{tid}.{cid}'
clients_net = '10.20.{tid}.{cid}'
vulnboxes_fw_rules = {
    'accept_io_ip': {
        'fw_input_ip_ip':'10.20.0.0/16',
        'fw_output_ip_ip':'10.20.0.0/16',
    },
}