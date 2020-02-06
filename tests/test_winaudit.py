from libs.winaudit import ADAudit, WinServerAudit


class TestWinAudit:
    """WinAudit Test cases.

    Methods:
    TestPlaceHolder - A test case to act as a placeholder.  It has no
    actual value and should be removed once other test cases have been
    developed."""
    def test_domain_admin_ex(self):
        audit_test = ADAudit()
        audit_test.domain_admins = ['bwayne', 'rgrayson', 'hdent']
        audit_test.get_domain_admin_ex()
        assert 'hdent' in audit_test.domain_admin_ex

    def test_local_admin_ex(self):
        audit_test = WinServerAudit()
        audit_test.local_admins = [{'host': 'krypton',
                                    'admins': ['kel', 'jel', 'dzod']}
                                   ]
        audit_test.get_local_admin_ex()
        assert 'dzod' in audit_test.local_admin_ex[0]['bad_admins']
