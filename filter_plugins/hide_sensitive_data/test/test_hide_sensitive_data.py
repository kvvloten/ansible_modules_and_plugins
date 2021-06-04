from roles.server_deploy.os_windows.filter_plugins.hide_sensitive_data import hide_sensitive_data


def test_hide_sensitive_data():
    hidden = hide_sensitive_data('IamAdmin')
    assert hidden == 'SQBhAG0AQQBkAG0AaQBuAFAAYQBzAHMAdwBvAHIAZAA='
