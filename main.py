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
    ldap_pwd = core.get_credentials(scss_dict)
    ldap_dict = {
        'ldap_url': config['domain']['ldap_url'],
        'bind_dn': config['domain']['ldap_dn'],
        'bind_pwd': ldap_pwd
    }
    server_ous = config['servers']['ous'].split('|')
    mail_info = {
        'sender': config['mail']['sender'],
        'recipients': config['mail']['rcpt'],
        'subject': config['mail']['subject'],
        'server': config['mail']['server'],
        'body': str()
    }
    # Running AD audit
    log_me.info('Beginning AD audit.')
    ad_audit = winaudit.ADAudit()
    # Getting domain admins.
    ad_audit.get_domain_admins(ldap_dict, config['domain']['adm_dn'])
    # Comparing list of domain admins against known good.
    ad_audit.get_domain_admin_ex()
    log_me.info('AD Audit complete.')
    # Running server local admin audit.
    log_me.info('Beginning server local admin audit.')
    server_audit = winaudit.WinServerAudit()
    # Getting server list.
    server_audit.get_servers(ldap_dict, server_ous)
    server_count = len(server_audit.host_list)
    # Getting local admins from each server.
    server_audit.get_local_admins()
    # Comparing list of local admins against known good.  Note: if no
    # data exists detailing the approved local admins on a server, all
    # local admins are assumed to be exceptions.
    server_audit.get_local_admin_ex()
    log_me.info('Server local admin audit complete.')
    # Creating a mail message.
    msg_body = '*' * 64 + '\n'
    msg_body = ('Domain Admin exceptions: ' +
                str(ad_audit.domain_admin_ex).strip('[]'))
    msg_body = msg_body + '\n'
    msg_body = msg_body + '*' * 64 + '\n'
    msg_body = msg_body + '%d hosts were audited.\n' % server_count
    msg_body = msg_body + 'Local Admin Exceptions:' + '\n'
    for local_admin_ex in server_audit.local_admin_ex:
        bad_admins = str(local_admin_ex['bad_admins']).strip('[]')
        msg_body = msg_body + (
            'Host name:%s Unapproved Local Admins:%s' + '\n' * 2
        ) % (local_admin_ex['host'], bad_admins)
    msg_body = msg_body + '*' * 64 + '\n'
    msg_body = msg_body + ('These hosts could not be audited.  Check ' +
                           'the log for details.' + '\n')
    msg_body = msg_body + str(server_audit.unreachable_servers)
    mail_info['body'] = msg_body
    core.mail_send(mail_info)


if __name__ == '__main__':
    main()
