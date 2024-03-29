from requests import post
from smtplib import SMTP, SMTPConnectError
from socket import gaierror, gethostbyname
from email.mime.text import MIMEText
from logging import getLogger

from pyotp import TOTP


def mail_send(mail_info):
    """Takes input, sends mail.

    Keyword arguments:
    mail_info - A dict() object with the following keys and
    corresponding values: sender, recipients, subject, server and
    body.

    Outputs:
    Sends an email, returns nothing.

    Raises:
    gaierror - Occurs when DNS resolution of a hostname fails.
    SMTPConnectError - Occurs when the remote SMTP sever refuses the
    connection."""
    # Defining mail properties.
    msg = MIMEText(mail_info['body'])
    msg['Subject'] = mail_info['subject']
    msg['From'] = mail_info['sender']
    msg['To'] = mail_info['recipients']
    # Obtaining IP address of SMTP server host name.  If using an IP
    # address, omit the gethostbyname function.
    try:
        s = SMTP(gethostbyname(mail_info['server']), '25')
    except gaierror:
        print('Hostname resolution of %s failed.' % mail_info['server'])
        exit(1)
    except SMTPConnectError:
        print('Unable to connect to %s, the server refused the ' +
              'connection.' % mail_info['server'])
        exit(1)
    # Sending the mail.
    s.sendmail(mail_info['sender'], mail_info['recipients'], msg.as_string())


def get_credentials(scss_dict):
    """Makes an API call to SCSS, returns credentials.

    Keyword Arguments:
    scss_dict - a dict() object containing the following keys with
    the correct corresponding values: api_key, otp, userid and url.

    Output:
    data - str(), the data returned from scss."""
    log = getLogger('WinAudit_Log')
    api_key = scss_dict['api_key']
    otp = TOTP(scss_dict['otp']).now()
    userid = scss_dict['userid']
    url = scss_dict['url']
    user_agent = 'scss-client'
    headers = {
        'User-Agent': user_agent,
        'api-key': api_key,
        'totp': otp,
        'userid': userid
    }
    scss_response = post(
        url,
        headers=headers,
        verify='ca-bundle.crt'
        )
    if scss_response.status_code == 200:
        data = scss_response.json().get('gpg_pass')
        log.debug('Credentials successfully retrieved from SCSS')
    else:
        log.error('Unable to retrieve credentials from SCSS.  The HTTP ' +
                  'error code is %s', scss_response.status_code)
        exit(1)
    return data
