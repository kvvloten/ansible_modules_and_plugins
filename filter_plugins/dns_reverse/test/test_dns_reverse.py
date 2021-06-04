from filter_plugins.dns_reverse.dns_reverse import get_reverse_zone, get_reverse_ip


def test_get_reverse_zone():
    assert get_reverse_zone('192.168.1.0/24') == '1.168.192.in-addr.arpa.'
    assert get_reverse_zone('192.168.1.128/25') == '128.1.168.192.in-addr.arpa.'
    assert get_reverse_zone('192.168.1.192/26') == '192.1.168.192.in-addr.arpa.'
    assert get_reverse_zone('192.168.1.32/27') == '32.1.168.192.in-addr.arpa.'
    assert get_reverse_zone('192.168.1.48/28') == '48.1.168.192.in-addr.arpa.'
    assert get_reverse_zone('192.168.1.56/29') == '56.1.168.192.in-addr.arpa.'


def test_get_reverse_ip():
    assert get_reverse_ip('192.168.1.1', '192.168.1.0/24') == '1'
    assert get_reverse_ip('192.168.1.1', '1.168.192.in-addr.arpa.') == '1'
    assert get_reverse_ip('192.168.1.129', '192.168.1.128/25') == '129'
    assert get_reverse_ip('192.168.1.193', '192.168.1.192/26') == '193'
    assert get_reverse_ip('192.168.1.35', '192.168.1.32/27') == '35'
    assert get_reverse_ip('192.168.1.58', '192.168.1.48/28') == '58'
    assert get_reverse_ip('192.168.1.58', '192.168.1.56/29') == '58'

    # Fails for networks larger than /24, implementation should use ip wildcard to make this work
    # assert get_reverse_ip('10.168.2.1', '10.0.0.0/8') == '1.2.168'
    # assert get_reverse_ip('10.168.2.1', '10.128.0.0/9') == '1.2.168'
