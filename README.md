# WinAudit
Windows auditing scripts

[![Known Vulnerabilities](https://snyk.io/test/github/bentleygd/WinAudit/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/bentleygd/WinAudit?targetFile=requirements.txt)[![Total alerts](https://img.shields.io/lgtm/alerts/g/bentleygd/WinAudit.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/bentleygd/WinAudit/alerts/)[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/bentleygd/WinAudit.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/bentleygd/WinAudit/context:python)![Lint and Test](https://github.com/bentleygd/WinAudit/workflows/Lint%20and%20Test/badge.svg)

## **Purpose**

The purpose of these scripts is to automate various Windows and Active Dirctory audits using Python.  Please note that this project makes use of the pywin32 module, and as such, is designed to run on a Windows platform.

Currently, this project supports the following audits:
- **Active Directory Built-In Administrator group membership**
- **Windows Server Local Administrator group membership**
- **Windows Log Sources for IBM Q-Radar**

# **Additional Documentation**

Additional documentation can be found [here](https://github.com/bentleygd/WinAudit/blob/master/DOCS.md)

# **Included Scripts**
Several scripts are included in this project, which are summarized below.

- **windows_audit.py** \- This script audits local administrator group membership for the servers specified in the server->ous portion of the configuration.  It also audits the built-in administrator group membership of Active Directory.
- **siem_report.py** \- This script enumerates the servers in the servers->ous portion of the configuratoin and compares them to the log sources in IBM's Q-Radar SIEM product.  

# **Example Config.cnf**

Below is an example of a configuration for this script.  By default, this script uses the **configparser** module that is in the Python standard library.

```
[ldap]
ldap_url = ldaps://ldap.example.com
ldap_dn = CN=ldap_bind_dn,OU=User Accounts,DC=example,DC=com

[servers]
ous = <server OUs go here sepearted by | >

[mail]
sender = AdminReview@24hourfit.com
subject = Microsoft Admin Security Review
rcpt = <recipient email address goes here>
server = <SMTP server goes here>

[domain_admins]
# All entries must be in lower case.
good_admins = administrator,sholmes,jwatson
adm_dn = CN=Administrators,CN=Builtin,DC=Example,DC=com

[siem]
log_source_endpoint = https://<q-radar-ip>/api/config/event_sources/log_source_management/log_sources?fields=name
# You'll need to implement your own encrypt/decrypt functions
token = <encrypted security token goes here>

[local_admins]
# All entries must be in lower case.
hostname = administrators,admin 1,admin 2
```

# **Reporting Issues**

You can report any issues, bugs or security vulnerabilities via the Issues tab [here](https://github.com/bentleygd/WinAudit/issues).
