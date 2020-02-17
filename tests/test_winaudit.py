from libs.winaudit import ADAudit, WinServerAudit


class TestWinAudit:
    """WinAudit Test cases.

    Methods:
    test_domain_admin_ex - A test case for the ADAudit.get_domain_admin_ex
    method.  This test verifies that the exception logic is working as
    intended.

    test_local_admin_ex - A test case for the WinServerAudit.local_admin_ex
    method.  This test verifies that the exception logic is working as
    intended."""
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
