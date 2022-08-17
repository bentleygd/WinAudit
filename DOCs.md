# **WinAudit Code Documentation**

# **ADAudit Class**

The ADAudit class is intended to be used to audit Windows Active Directory or to obtain information from Active Directory to support the audit methods of subclasses or other functions.

## **ADAudit instance variables**

- **server_list** \- A list object containing the hostnames of Windows Servers to be audited for server specific audits by the WinServerAudit class.  This list is populated by the ADAudit.get_servers method.  This list is used by the following classes: WinServerAudit.get_local_admins and WinServerAudit.get_siem_source_ex methods.
- **domain_admin_ex** \- A list object containing the SAM account name of accounts that are not designated domain administrators.  This list should always be empty.  This list is populated by the ADAudit.get_domain_admin_ex method and relies on the ADAudit.domain_admins instance variable.  It is also dependant on the static list of approved administrators in the configuration file.
- **domain_admins** \- A list object containing the user names of the members of the builtin administrators group.  If a group member is another group, the user names of that group are added to the list so that there are no nested groups.  This list is populated by the ADAudit.get_domain_admins method.  This variable is used by the ADAudit.get_domain_admin_ex method.
- **log_me** \- This is a call for the getLogger class from the logger module in the Python standard library.
- **config_file** \- This is the file name of the configuration file that will be called by the ConfigParser class from the configparser module.
- **config** \- This is the instantiation of the ConfigParser class from the configparser module.  This configuration will be used by this class (and sub-classes).

## **ADAudit class methods**

- **get_servers** \- This method populates the ADAudit.server_list instance variable with the hostnames of the servers in the Active Directory OUs that are specified in the ADAudit.config file.  The connection to Active Directory is made using the ldap3 module.  This method has two required positional arguments: ldap_dict and server_ous.  ldap_dict is a dictionary that requires the following keys: ldap_url, bind_dn, bind_pwd.  server_ous is a list of OUs that contain the servers to be audited.  This method raises LDAPExceptionError if it is unable to connect to the LDAP specified in the ldap_url key of the ldap_dict and logs the exception information.

**Code Example**
```python
from configparser import ConfigParser

from libs.winaudit import ADAudit


# Instantiating the ADAudit class.
windows_audit = ADAudit()
# Setting the positional arguments required by the get_servers method.
# ldap_url is the URL of the LDAP server we are connecting to.
# bind_dn is the user name used to bind to LDAP.
# bind_pwd is the password for the user specified in bind_dn.
ldap_dict = {
    'ldap_url': config['ldap']['ldap_url'],
    'bind_dn': config['ldap']['bind_dn'],
    'bind_pwd': 'super secret password' # Never store passwords in clear text
}
# We are storing the server OUs in a pipe delimited value in the config
# file, so we split them to make them a list.
server_ous = config['servers']['ous'].split('|')
# Populating the self.server_list variable by invoking the get_servers
# method.
windows_audit.get_servers(ldap_dict, server_ous)
# Iterating through self.server_list and printing each host name.
for server in windows_audit.server_list:
    print(server)
```

- **audit_domain_admins** \- This method populates the ADAudit.domain_admins instance variable with the members of the built-in administrator group in Active Diretory.  This method connects to Active Directory using the ldap3 module.  The ADAudit.get_domain_admin_ex module is depdendent upon the execution of this module as it relies on the ADAudit.domain_admins variable.  This method has one required positional argument: ldap_dict.  ldap_dict is a dictionary that requires the following keys: ldap_url, bind_dn, bind_pwd.  This method raises the LDAPExceptionError if the connection to LDAP is unsuccessful.

**Code Example**
```python
from configparser import ConfigParser

from libs.winaudit import ADAudit


# Instantiating the ADAudit class.
example_audit = ADAudit()
# Instantiating the ConfigParser class and loading the configuration
# file.
config = ConfigParser()
config.read('config.cnf')
# Configuring the ldap_dict positional argument.
ldap_dict = {
    'ldap_url': config['ldap']['ldap_url'],
    'bind_dn': config['ldap']['bind_dn'],
    'bind_pwd': SecretSquirrelPassword  # Never store passwords in code
}
# ldap_url is the URL that LDAP will bind to.  Exmaple: ldaps://hostname.domain.com
# 
# bind_dn is the user name that will be used to connect to LDAP.  It must be in 
# LDAP distinguished name format.  Example: CN=username,,OU=User Accounts,DC=example,DC=com
#
# bind_pwd is the password of the user specified in bind_dn.
#
# Running the audit_domain_admins method.
example_audit.audit_domain_admins(ldap_dict)
# Remember that no data is returned and that the results are stored in self.domain_admins.
for admin in example_audit.domain_admins:
    print(admin)
```

- **get_domain_admin_ex** \- This method populates the ADAudit.domain_admin_ex instance variable.  This method relies on the ADAudit.domain_admins instance variable and, therefore, relies on the execution of the ADAudit.audit_domain_admins method.  This method checks to see if each member of the domain admin group retrieved from Active Directory is a known, approved admin by comparing the list retrieved from Active Directory to a list of admins stored in a configuration file.

**Code Example**
```python
from configparser import ConfigParser

from libs.winaudit import ADAudit


# Instantiating the ADAudit class.
example_audit = ADAudit()
# Loading the configuration file.
config = ConfigParser()
config.read('config.cnf')
# Setting the ldap_dict variable which will be used as a positional argument by
# the ADAudit.audit_domain_admins method.
ldap_dict = {
    'ldap_url': config['ldap']['ldap_url'],
    'bind_dn': config['ldap']['bind_dn'],
    'bind_pwd': SecretSquirrelPassword  # Never store passwords in code
}
# ldap_url is the URL that LDAP will bind to.  Exmaple: ldaps://hostname.domain.com
# 
# bind_dn is the user name that will be used to connect to LDAP.  It must be in 
# LDAP distinguished name format.  Example: CN=username,,OU=User Accounts,DC=example,DC=com
#
# bind_pwd is the password of the user specified in bind_dn.
#
# Running the audit_domain_admins method.
example_audit.audit_domain_admins(ldap_dict)
# Now that we have the domain admins, we can call the ADAudit.get_domain_admin_ex method.
example_audit.get_domain_admin_ex()
# As with the other methods, the results are stored in an instance variable.
for audit_exception in example_audit.domain_admin_ex:
    print(audit_exception)
```

# **WinServerAudit Class**

The WinServerAudit class is a Windows Server auditing class that is a subclass of the ADAudit class.  This class makes use of the pywin32 Python module and must be run from a Windows server since pywin32 does not natively run on Linux.

## **WinAuditServer instance variables**

- **local_admins** \- A list() object of dict() ojbects that contain the local administrators for each host that is audited.  Example: {'hostname': 'host1.example.com', 'admins:' ['admin1', 'admin2']}.  This variable is populated by the WinServerAudit.get_local_admins method.  This variable is used by the get_admin_ex_method.
- **bad_admins** \- A list() object of dict() ojbects that contain local administrators that do are not listed as the approved administrators for that host.  Example: {'hostname': 'host1.example.com', 'admins:' ['bad_admin1', 'evil_admin']}.  This variable is populated by the get_admin_ex method.
- **unreachable_servers** \- A list() object of server names that is generated by exceptions from get_local_admins, which implies that these servers are either down or that the account used while running the audit does not have sufficient permissions to audit the host.
- **reachable_servers** \-  A list() ojbect of servers that were successfully audited during get_local_admins().
- **no_log_servers** \- A list() object of servers that are not configured as log sources in a SIEM.  This variable is populated by the get_siem_source_ex method.

## **WinServerAudit class methods**

- **get_local_admins** \- This method connects to a list of servers via the NetLocalGroupGetMembers function from pywin32 and enumerates the local administrator group.  The list of servers is provided by the WinServerAudit.server_list instance attribute.  Thus, this method is dependent upon the execution of the WinServerAudit.get_servers method (which is a method of WinServerAudit's parent class).  The WinServerAudit.local_admins instance variable is populated by this method.  The WinServerAudit.get_admin_ex method is dependent upon the execution of this method.

**Code Example**
```python
from configparser import ConfigParser

import libs.winaudit as win_aud


# Instantiating the ADAudit class.
windows_audit = win_aud.WinServerAudit()
# Setting the positional arguments required by the get_servers method.
# ldap_url is the URL of the LDAP server we are connecting to.
# bind_dn is the user name used to bind to LDAP.
# bind_pwd is the password for the user specified in bind_dn.
ldap_dict = {
    'ldap_url': config['ldap']['ldap_url'],
    'bind_dn': config['ldap']['bind_dn'],
    'bind_pwd': 'super secret password' # Never store passwords in clear text
}
# We are storing the server OUs in a pipe delimited value in the config
# file, so we split them to make them a list.
server_ous = config['servers']['ous'].split('|')
# Populating the self.server_list variable by invoking the get_servers
# method.
windows_audit.get_servers(ldap_dict, server_ous)
# Obtaining local administrator group membership of each server in the
# windows_audit.server_list variable
windows_audit.get_local_admins()
# Iterating through and printing the audit results.
for admin_info in windows_audit.local_admins:
    print('The local admins for %s are: %s') %
    (admin_info['host'], admin_info['admins'])
```

- **get_local_admin_ex** \- This method uses the lists of local administrators generated by the WinServerAudit.get_local_admins method and compares it to the lists of local administrators stored in the configuration file as known good admins.  See the local_admins section of the congfiuration file provided in REAMDE.md for an example.  This method is depdenent upon the WinServerAudit.get_local_admins method to generate the list of local admins.  This method populates the WinServerAudit.bad_admins instance variable.

**Code Example**
```python
from configparser import ConfigParser

import libs.winaudit as win_aud


# Instantiating the ADAudit class.
windows_audit = win_aud.WinServerAudit()
# Setting the positional arguments required by the get_servers method.
# ldap_url is the URL of the LDAP server we are connecting to.
# bind_dn is the user name used to bind to LDAP.
# bind_pwd is the password for the user specified in bind_dn.
ldap_dict = {
    'ldap_url': config['ldap']['ldap_url'],
    'bind_dn': config['ldap']['bind_dn'],
    'bind_pwd': 'super secret password' # Never store passwords in clear text
}
# We are storing the server OUs in a pipe delimited value in the config
# file, so we split them to make them a list.
server_ous = config['servers']['ous'].split('|')
# Populating the self.server_list variable by invoking the get_servers
# method.
windows_audit.get_servers(ldap_dict, server_ous)
# Obtaining local administrator group membership of each server in the
# windows_audit.server_list variable
windows_audit.get_local_admins()
# Running the local admin audit.
windows_audit.get_local_admin_ex()
# Printing the results of the local admin audit.
for local_admin_ex in server_audit.local_admin_ex:
    bad_admins = str(local_admin_ex['bad_admins']).strip('[]')
    print(
        'Host name:%s\nUnapproved Local Admins:%s' + '\n' * 2
        ) % (local_admin_ex['host'], bad_admins)
```

- **get_siem_sources** \- This method connects to the Q-Radar log sources endpoint (configured via the siem section of the configuration) and retrieves the names of all log sources.  This method uses the requests module (requests documentation can be found [here](https://requests.readthedocs.io/en/latest/)) to connect to the log sources endpoint.  This method returns a list() object of the JSON responses from the Q-Radar API.  This method raises a HTTPError exception if the Q-Radar API returns a non-200 response.

**Code Example**
```python
from libs.winaudit import WinServerAudit


# Instantiating the WinServerAudit class.
win_audit = WinServerAudit()
# Getting a list of log sources from Q-Radar.
log_sources = win_audit.get_siem_sources()
# Printing the log sources.
for source in log_souces:
    print(source)
```

- **get_siem_source_ex** \- This method checks to see if the Windows servers in the WinServerAudit.server_list instance variable are configured as log sources by comparing them to the log sources returned by the WinServerAudit.get_siem_sources method.  This method populates the WinServerAudit.no_log_servers instance variable.  This method is dependent upon the WinServerAudit.get_siem_sources method and the WinServerAudit.get_servers method.

**Code Example**
```python
from configparser import ConfigParser

from libs.winaudit import WinServerAudit


# Loading the configuration file.
config = ConfigParser()
config.read('config.cnf')
# Retrieving the ldap_info configuration.
# ldap_url is the URL of the LDAP server we are connecting to.
# bind_dn is the user name used to bind to LDAP.
# bind_pwd is the password for the user specified in bind_dn.
ldap_info = {
    'ldap_url': config['ldap']['ldap_url'],
    'bind_dn': config['ldap']['ldap_dn'],
    'bind_pwd': 'ldap_pwd' # Never store passwords in code or in clear text.

}
# Retrieving the server OUs from the configuration file.
server_ous = config['servers']['ous'].split('|')
# Instantiating the WinServerAudit class and beginning the audit.
win_audit = WinServerAudit()
# Generating a list of Windows servers from the OUs specified in the
# configuration file.
win_audit.get_servers(ldap_info, server_ous)
# Getting a list of log sources from Q-Radar.
log_sources = win_audit.get_siem_sources()
# Generating log source exception list.  Note: the exceptions are stored
# in the self.no_log_sources instance variable
win_audit.get_siem_source_ex(log_sources)
# Iterating through the results.
print('The following servers are not configured as log sources:\n')
for server in win_audit.no_log_servers:
    print(server)
```