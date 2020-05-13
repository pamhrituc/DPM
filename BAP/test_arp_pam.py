from arp_pam import get_ips_by_mac, get_arp_cache

cache = {'192.168.0.1': '11:22:33:44:55:66', '192.168.0.2': '22:33:44:55:66:77', '192.168.0.3': '11:22:33:44:55:66'}

def test_1_get_ips_by_mac():
    mac_1 = '11:22:33:44:55:66'
    expected_1 = ['192.168.0.1', '192.168.0.3']
    assert(get_ips_by_mac(cache, mac_1) == expected_1)

def test_2_get_ips_by_mac():
    mac_2 = '22:33:44:55:66:77'
    expected_2 = ['192.168.0.2']
    assert(get_ips_by_mac(cache, mac_2) == expected_2)

def test_3_get_ips_by_mac():
    mac_3 = '33:44:55:66:77:88'
    expected_3 = []
    assert(get_ips_by_mac(cache, mac_3) == expected_3)
