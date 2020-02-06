from logging import getLogger, basicConfig, INFO
from configparser import ConfigParser

import libs.winaudit as winaudit
import libs.core as core


def main():
    """Main function.
    This is used to avoid accidental code execution."""
    # Setting up logging.
    log_me = getLogger('WinAudit_Log')
    basicConfig(
        format='%(asctime)s %(name)s %(levelname)s: %(message)s',
        datefmt='%m/%d/%Y %H:%M:%S',
        level=INFO,
        filename='win_audit.log'
    )
    # Parsing configuration file.
    config = ConfigParser()
    config.read('config.cnf')
    # Retrieving or setting info needed for audit.
    scss_dict = {
        'url': config['scss']['url'],
        'api_key': config['scss']['api'],
        'otp': config['scss']['otp'],
        'userid': config['scss']['user']
    }
    print(scss_dict['api_key'])
    ldap_pwd = core.get_credentials(scss_dict)
    ldap_dict = {
        'ldap_url': config['domain']['ldap_url'],
        'ldap_dn': config['domain']['ldap_dn'],
        'bind_pwd': ldap_pwd
    }
    # Running audit
    log_me.info('Beginning AD audit.')
    ad_audit = winaudit.ADAudit()
    ad_audit.get_domain_admins(ldap_dict, config['domain']['adm_dn'])
    ad_audit.get_domain_admin_ex()
    log_me.info('AD Audit complete.')
    print(ad_audit.domain_admin_ex)


if __name__ == '__main__':
    main()
