from libs.winaudit import ADAudit, WinServerAudit


class TestWinAudit:
    """WinAudit Test cases.

    Methods:
    TestPlaceHolder - A test case to act as a placeholder.  It has no
    actual value and should be removed once other test cases have been
    developed."""
    def test_domain_admin_ex(self):
        _class_test = ADAudit()
        _class_test.config_file = 'test.conf'
        _class_test.config.read(_class_test.config_file)
        _class_test.domain_admins = ['bwayne', 'rgrayson', 'hdent']
        _class_test.get_domain_admin_ex()
        assert 'hdent' in _class_test.domain_admin_ex

    def test_local_admin_ex(self):
        _class_test = WinServerAudit()
        _class_test.config_file = 'test.conf'
        _class_test.config.read(_class_test.config_file)
        _class_test.local_admins = [{'host': 'krypton',
                                     'admins': ['kel', 'jel', 'dzod']}
                                    ]
        _class_test.get_local_admin_ex()
        assert 'dzod' in _class_test.local_admin_ex[0]['bad_admins']
