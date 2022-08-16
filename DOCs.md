# WinAudit Code Documentation

**ADAudit Class**

The ADAudit class is intended to be used to audit Windows Active Directory or to obtain information from Active Directory to support the audit methods of subclasses or other functions.

The ADAudit class has the following instance variables:

- **server_list** \- A list object containing the hostnames of Windows Servers to be audited for server specific audits by the WinServerAudit class.  This list is populated by the ADAudit.get_servers method.  This list is used by the following classes: WinServerAudit.get_local_admins and WinServerAudit.get_siem_source_ex methods.
- **domain_admin_ex** \- A list object containing the SAM account name of accounts that are not designated domain administrators.  This list should always be empty.  This list is populated by the ADAudit.get_domain_admin_ex method and relies on the ADAudit.domain_admins instance variable.  It is also dependant on the static list of approved administrators in the configuration file.
- **domain_admins** \- A list object containing the user names of the members of the builtin administrators group.  If a group member is another group, the user names of that group are added to the list so that there are no nested groups.  This list is populated by the ADAudit.get_domain_admins method.  This variable is used by the ADAudit.get_domain_admin_ex method.
- **log_me** \- This is a call for the getLogger class from the logger module in the Python standard library.
- **config_file** \- This is the file name of the configuration file that will be called by the ConfigParser class from the configparser module.
- **config** \- This is the instantiation of the ConfigParser class from the configparser module.  This configuration will be used by this class (and sub-classes).

The ADAudit class has the following methods:

- **get_servers** \- This method populates the ADAudit.server_list instance variable with the hostnames of the servers in the Active Directory OUs that are specified in the ADAudit.config file.  This method has two required positional arguments: ldap_dict and server_ous.  ldap_dict is a dictionary containing the following keys: ldap_url, bind_dn, bind_pwd.  server_ous is a list of OUs that contain the servers to be audited.  This method raises LDAPExceptionError if it is unable to connect to the LDAP specified in the ldap_url key of the ldap_dict.

**Code Example**
```python
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