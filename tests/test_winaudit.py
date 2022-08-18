from configparser import ConfigParser
from ssl import PROTOCOL_TLS_CLIENT

from ldap3 import Connection, Server, Tls
from ldap3.core.exceptions import LDAPExceptionError

from libs.winaudit import ADAudit, WinServerAudit
from libs.core import get_credentials


class TestAuditConfig:
    def test_ldap_config(self):
        config = ConfigParser()
        config.read('config.cnf')
        if 'ldap_url' and 'ldap_dn' in list(config['ldap']):
            test = True
        else:
            test = False
        assert test is True

    def test_servers_config(self):
        config = ConfigParser()
        config.read('config.cnf')
        if 'ous' in list(config['servers']):
            test = True
        else:
            test = False
        assert test is True

    def test_domain_admins_config(self):
        config = ConfigParser()
        config.read('config.cnf')
        if 'good_admins' and 'adm_dn' in list(config['domain_admins']):
            test = True
        else:
            test = False
        assert test is True

    def test_siem_config(self):
        config = ConfigParser()
        config.read('config.cnf')
        if 'log_source_endpoint' and 'token' in list(config['siem']):
            test = True
        else:
            test = False
        assert test is True

    def test_mail_config(self):
        config = ConfigParser()
        config.read('config.cnf')
        if (
            'sender' and
            'subject' and
            'rcpt' and
            'server' in list(config['mail'])
                ):
            test = True
        else:
            test = False
        assert test is True


class TestLDAPConnections:
    def test_ldap_connection(self):
        config = ConfigParser()
        config.read('config.cnf')
        tls_config = Tls(
            version=PROTOCOL_TLS_CLIENT,
            ca_certs_file='ca-bundle.crt'
        )
        scss_dict = {
            'url': config['scss']['url'],
            'api_key': config['scss']['api'],
            'otp': config['scss']['otp'],
            'userid': config['scss']['user']
        }
        l_pwd = get_credentials(scss_dict)
        server = Server(
            config['ldap']['ldap_url'],
            use_ssl=True,
            tls=tls_config
            )
        try:
            conn = Connection(
                server,
                user=config['ldap']['ldap_dn'],
                password=l_pwd,
                auto_bind=True
            )
        except LDAPExceptionError:
            test = False
        if conn:
            test = True
        conn.unbind()
        assert test is True

    def test_server_data(self):
        config = ConfigParser()
        config.read('config.cnf')
        scss_dict = {
            'url': config['scss']['url'],
            'api_key': config['scss']['api'],
            'otp': config['scss']['otp'],
            'userid': config['scss']['user']
        }
        l_pwd = get_credentials(scss_dict)
        ldap_data = {
            'ldap_url': config['ldap']['ldap_url'],
            'bind_dn': config['ldap']['ldap_dn'],
            'bind_pwd': l_pwd
        }
        server_ous = config['servers']['ous'].split('|')
        test_audit = ADAudit()
        test_audit.get_servers(ldap_data, server_ous)
        assert len(test_audit.server_list) > 0

    def test_domain_admin_data(self):
        config = ConfigParser()
        config.read('config.cnf')
        scss_dict = {
            'url': config['scss']['url'],
            'api_key': config['scss']['api'],
            'otp': config['scss']['otp'],
            'userid': config['scss']['user']
        }
        l_pwd = get_credentials(scss_dict)
        ldap_data = {
            'ldap_url': config['ldap']['ldap_url'],
            'bind_dn': config['ldap']['ldap_dn'],
            'bind_pwd': l_pwd
        }
        test_audit = ADAudit()
        test_audit.audit_domain_admins(ldap_data)
        assert len(test_audit.domain_admins) > 0


class TestServerConnections:
    def test_local_admin_data(self):
        config = ConfigParser()
        config.read('config.cnf')
        scss_dict = {
            'url': config['scss']['url'],
            'api_key': config['scss']['api'],
            'otp': config['scss']['otp'],
            'userid': config['scss']['user']
        }
        l_pwd = get_credentials(scss_dict)
        ldap_data = {
            'ldap_url': config['ldap']['ldap_url'],
            'bind_dn': config['ldap']['ldap_dn'],
            'bind_pwd': l_pwd
        }
        server_ous = config['servers']['ous'].split('|')
        test_audit = WinServerAudit()
        test_audit.get_servers(ldap_data, server_ous)
        test_audit.get_local_admins()
        assert len(test_audit.local_admins) > 0

    def test_siem_sources(self):
        test_audit = WinServerAudit()
        siem_sources = test_audit.get_siem_sources()
        assert len(siem_sources) > 0
