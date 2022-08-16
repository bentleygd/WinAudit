from logging import getLogger
from time import time
from configparser import ConfigParser
from ssl import PROTOCOL_TLS_CLIENT

from ldap3 import Connection, Server, SUBTREE, BASE, Tls
from ldap3.core.exceptions import LDAPExceptionError
from win32.win32net import NetLocalGroupGetMembers as NLGGM
from requests import get, HTTPError


class ADAudit():
    def __init__(self):
        """An active directory audit object.

        Attributes:
        self.server_list = list(), a list of Windows Servers to audit.
        self.domain_admin_ex = list(),a list objecs containing the
        user names of accounts that should not have domain admin
        privileges.  If this list is not empty, you have problems.
        self.domain_admins = list(), members of the domain admin group.
        self.log_me = str(), the name of the logger instance for
        logging.
        self.config_file = file(), the config file to parse with
        ConfigParser()
        self.config = ConfigParser(), self-explanatory.
        self.config.read(self.config_file), Initializing ConfigParser
        in order to read self.config.

        Methods:
        get_servers = populates self.host_list with a list of servers
        in Active directory via LDAP.
        get_domain_admins = populates self.domain_admins with a list of
        domain admins.
        get_domain_admin_ex = compares list of admins retrieved from AD
        against a list of instrumented admins and returns the
        difference."""
        self.server_list = []
        self.domain_admin_ex = []
        self.domain_admins = []
        self.log_me = getLogger(__name__)
        self.config_file = 'config.cnf'
        self.config = ConfigParser()
        self.config.read(self.config_file)

    def get_servers(self, ldap_dict, server_ous):
        """Returns a list of servers in specific OUs.

        Inputs:
        ldap_dict - dict(), a dictionary containing the following keys:
        ldap_url, bind_dn, bind_pwd
        server_ous - list(), a list of server OUs.  We will iterate
        throug this list to obtain all servers in a given OU.

        Outputs:
        self.server_list, a list of servers in server_ous.  This list
        is updated but not returned.  The contents of the list can be
        accessed by accessing the instance variable.

        Rasies:
        LDAPExceptionError - Base LDAP exception class for catching LDAP
        errors."""
        raw_data = []
        # Setting constants to reduce future line length
        # This is the LDAP URL (i.e., the server you connect to)
        l_url = ldap_dict['ldap_url']
        # The BIND DN is the user name used in the connection.
        bind_dn = ldap_dict['bind_dn']
        # This the password used to connect to LDAP.
        l_passwd = ldap_dict['bind_pwd']
        # This is the TLS configuration used by the LDAP connection.
        # We are disabling certificate validation to avoid
        tls_config = Tls(
            version=PROTOCOL_TLS_CLIENT,
            ca_certs_file='ca-bundle.crt'
        )
        # Connecting to LDAP server (i.e., a domain controller)
        server = Server(l_url, use_ssl=True, tls=tls_config)
        try:
            conn = Connection(
                server,
                user=bind_dn,
                password=l_passwd,
                auto_bind=True
            )
        except LDAPExceptionError:
            self.log_me.exception('Error occurred connecting to LDAP server.')
        # Setting an LDAP filter.
        filter = ('(&(objectClass=computer)(objectCategory=CN=Computer,' +
                  'CN=Schema,CN=Configuration,DC=24hourfit,DC=com))')
        # Iterating through each OU specified in search_ous to populate
        # self.server_list with server names retreived from LDAP.
        for ou in server_ous:
            search_data = conn.extend.standard.paged_search(
                ou,
                filter,
                search_scope=SUBTREE,
                attributes=['sAMAccountName'],
                paged_size=500,
            )
            for data in search_data:
                raw_data.append(data['raw_attributes'])
        for server in raw_data:
            server_name = server['sAMAccountName'][0].decode().lower()
            self.server_list.append(server_name)
        # Unbinding LDAP object to free up resources.
        conn.unbind()
        self.log_me.info(
            '%d servers added to audit population.' % len(self.server_list)
        )
        # Checking the host list to make sure that it has a reasonable
        # population.
        if len(self.server_list) < 20:
            self.log_me.error(
                'Server list only contains %d members.' % len(self.server_list)
            )

    def audit_domain_admins(self, ldap_dict):
        """Returns a list of unauthorized domain admins.

        Keyword Arguments:
        ldap_dict - dict(), a dictionary containing the following keys:
        ldap_url, bind_dn, bind_pwd

        Returns:
        admin_list - list(), A list of dictionaries containing domain
        admins.

        Raises:
        LDAPExceptionError - Occurs when the LDAP3 functions generate an
        error.  The base class for all LDAPExcetionErrors is used so that
        the log.exception call will catch the detailed exception while not
        missing any potential exceptions."""
        # Setting constants to reduce future line length
        # This is the LDAP URL (i.e., the server you connect to)
        l_url = ldap_dict['ldap_url']
        # The BIND DN is the user name used in the connection.
        bind_dn = ldap_dict['bind_dn']
        # This the password used to connect to LDAP.
        l_passwd = ldap_dict['bind_pwd']
        # This is the TLS configuration used by the LDAP connection.
        # Creating list of approved admins.
        # approved_admins = (
        #    self.config['domain_admins']['good_admins'].split(',')
        # )
        # Creating variables to use later.
        admin_list = []
        admin_groups = []
        # Connecting to LDAP.
        tls_config = Tls(
            version=PROTOCOL_TLS_CLIENT,
            ca_certs_file='ca-bundle.crt'
            )
        server = Server(l_url, use_ssl=True, tls=tls_config)
        try:
            conn = Connection(
                server,
                user=bind_dn,
                password=l_passwd,
                auto_bind=True
            )
        except LDAPExceptionError:
            self.log_me.exception('Error occurred connecting to LDAP server.')
        # Getting admins
        builtin_admins = conn.extend.standard.paged_search(
            self.config['domain_admins']['adm_dn'],
            '(objectClass=group)',
            search_scope=SUBTREE,
            attributes=['member'],
            paged_size=50,
            generator=False
        )
        # Determining if the built-in admininstrator group member is a
        # group or a user.  If it is a group, enumerating that groups
        # members as well.
        ldap_filter = '(|(objectClass=group)(objectClass=user))'
        for builtin_admin in builtin_admins[0]['attributes']['member']:
            search_base = builtin_admin
            admin_data = conn.extend.standard.paged_search(
                search_base,
                ldap_filter,
                BASE,
                attributes=['sAMAccountName', 'distinguishedName',
                            'objectClass', 'description'],
                paged_size=100,
                generator=False
            )
            # Checking to see if the group member is a group.
            if 'group' in admin_data[0]['attributes']['objectClass']:
                admin_groups.append(
                    admin_data[0]['attributes']['distinguishedName']
                )
            # Checking to see if the group member is a user.
            elif 'user' in admin_data[0]['attributes']['objectClass']:
                admin_list.append({
                    'name': admin_data[0]['attributes']['sAMAccountName'],
                    'desc': admin_data[0]['attributes']['description'][0],
                })
        # Retrieving nested group information.  If the group member is
        # a user, we append it to admin_list.  If the group member is
        # a group, we append it to admin_groups.  This process is
        # repeated until there are no more groups (we ahve a list of
        # only users).
        while len(admin_groups) > 0:
            entry = admin_groups.pop(0)
            admin_data = conn.extend.standard.paged_search(
                entry,
                ldap_filter,
                BASE,
                attributes=['sAMAccountName', 'distinguishedName',
                            'objectClass', 'description', 'member'],
                paged_size=100,
                generator=False
            )
            # Checking to see if the member is a user.  If it is not
            # already in the admin_list, append it to the admin_list.
            if 'user' in admin_data[0]['attributes']['objectClass']:
                admin_data = {
                    'name': admin_data[0]['attributes']['sAMAccountName'],
                    'desc': admin_data[0]['attributes']['description'][0]
                }
                if admin_data not in admin_list:
                    admin_list.append(admin_data)
            # Checking to see if the group member is a group.
            elif 'group' in admin_data[0]['attributes']['objectClass']:
                for member in admin_data[0]['attributes']['member']:
                    admin_groups.append(member)
        # Unbinding ldap object.
        conn.unbind()
        for admin in admin_list:
            self.domain_admins.append(admin['name'])

    def get_domain_admin_ex(self):
        """Populates self.domain_admin_ex with list of bad admins.

        Inputs:
        config['domain_admins']['good_admins'] - A list of approved
        domain admins.

        Outputs:
        self.domain_admin_ex - list(), A list of accounts that are in
        the domain admin group that do not have appropriate access.
        If this list is not empty, you have problems."""
        # Performing list comparison of domain admins gathered via
        # an LDP query against the list of known good admins.
        known_admins = self.config['domain_admins']['good_admins'].split(',')
        for admin in self.domain_admins:
            if admin.lower() not in known_admins:
                # If there is a domain admin that is not on the approved
                # list, append it to the list.
                self.domain_admin_ex.append(admin)
                # Let's log the fact that there is a bad domain admin.
                # If anything is log worthy, it is a bad domain admin.
                self.log_me.warning(
                    '%s is not an approved domain admin' % admin
                )


class WinServerAudit(ADAudit):
    def __init__(self):
        """A Windows server auditing object.

        Attributes:
        ADAudit.__init__(self) = Inherited attributes from the ADAudit
        class.
        self.local_admins = list() , A list of dictionaries containing
        the following keys: host (self explanatory), admins (self
        explanatory).
        self.local_admin_ex = list(), A list of dictionaries containing
        the following keys: host (self explanatory), bad_admins (self
        explanatory).
        self.unreachable_servers = list(), A list of servers that is
        generated by exceptions from get_local_admins, which implies
        that these servers are either down or that the account used
        while running the audit does not have sufficient permissions to
        audit the host.
        self.reachable_servers = list(), A list of servers that were
        successfully audited during get_local_admins().
        self.no_log_servers = list(), A list of servers that are not
        configured as log sources in a SIEM.

        Methods:
        get_local_admins - Gets all of the local administrators from the
        parent attribute of host list.
        get_admin_ex - Generates a list of user accounts that are not
        authorized to have local admin rights.
        get_siem_sources - Retrieves a list of log sources from IBM's
        Q-Radar SIEM.
        get_siem_source_ex - Generates a list of servers that are not
        reporting in to the Q-Radar SIEM."""
        ADAudit.__init__(self)
        self.local_admins = []
        self.local_admin_ex = []
        self.unreachable_servers = []
        self.reachable_servers = []
        self.no_log_servers = []

    def get_local_admins(self):
        """Retrieves the local admins from a Windows server.

        Inputs:
        self.host_list - list(), A list of hosts that is pouplated by
        the get_servers method inherited from the ADAudit class.

        Outputs:
        self.local_admins - list(), A list of users that are in the
        server's local administrator group.

        Raises:
        Exception - Generic exception that may occur when attempting to
        connect to a server."""
        # Connect to each server, and retrieve the domain and name of
        # the local administrators group.
        for server in self.server_list:
            server = str(server).strip('$')
            local_admins = []
            try:
                admin_data = NLGGM(r'\\' + server, 'administrators', 1)
            except Exception:
                self.log_me.exception('Unable to connect to %s.' % server)
                self.unreachable_servers.append(server)
            self.reachable_servers.append(server)
            for data in admin_data[0]:
                local_admins.append(data['name'])
            # Append the server name and list of local admins to the
            # local admins attribute.  This will be referenced later in
            # get_local_admin_ex.
            self.local_admins.append(
                {'host': server, 'admins': local_admins}
            )

    def get_local_admin_ex(self):
        """Populates self.local_admin_ex with list of bad admins.

        Inputs:
        self.local_admins - list(), an attribue that is populated by
        get_local_admins.

        Outputs:
        self.local_admin_ex - list(), A list of accounts that are in
        the local admin group that do not have appropriate access."""
        bad_admins = []
        self.log_me.debug('Running local admin audit')
        # Generating admin exception data.
        start = time()
        for data in self.local_admins:
            # Creating the dictionary for each iteration of local admin
            # data.
            bad_admin_data = {'host': data['host'], 'bad_admins': []}
            # Matching the hostname to the hosts in the config file to
            # check against list of approved admins.
            if data['host'].lower() in self.config['local_admins'].keys():
                # If the local admin is not in the approved list,
                # append to the bad_admin key in the bad_admins_data
                # dictionary.
                for admin in data['admins']:
                    admin_list = (
                        self.config['local_admins'][data['host']].split(',')
                    )
                    if admin.lower() not in admin_list:
                        bad_admin_data['bad_admins'].append(admin)
                        self.log_me.debug('%s is an unapproved admin' % admin)
                    else:
                        self.log_me.debug('%s is an approved admin' % admin)
            else:
                self.log_me.error('%s has no list of approved admins' % (
                    data['host'])
                )
                # If there is no data that specifies which admins are
                # good on a server, assume they're all bad to ensure
                # that they are reviewed.
                for admin in data['admins']:
                    bad_admin_data['bad_admins'].append(admin)
            bad_admins.append(bad_admin_data)
        for bad_admin in bad_admins:
            # If there are bad admins, append the hostname and the list
            # of bad admins to the local_admin_ex attribute. Otherwise,
            # do nothing.
            if len(bad_admin['bad_admins']) > 0:
                self.local_admin_ex.append(bad_admin)
                # Let's create a log for bad local admins.  It is log
                # worthy.
                self.log_me.warning(
                    '%s has unapproved local administrators' % (
                        bad_admin['host'])
                )
        end = time()
        _elapsed = end - start
        elapsed = int(round(_elapsed, 0))
        self.log_me.debug('Admin audit completed in %d seconds' % elapsed)

    def get_siem_sources(self):
        """Retrieves the list of log source names from IBM's Q-Radar SIEM.

        Required Input:
        None.

        Output:
        source_list = list(), A list of log source names parsed from the
        JSON repsonse returned by the Q-Radar log source API.

        Exceptions:
        HTTPError - Returned when there is an error connecting to the
        log source endpoint."""
        source_list = []
        # Configuring the request to the Q-Radar endpoint
        url = self.config['siem']['log_source_endpoint']
        params = {'fields': 'name'}
        headers = {
            'version': '16.0',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'SEC': self.config['siem']['token']
        }
        # Making the request.  Since Q-Radar uses a self signed cert, we
        # are disabling SSL validation.  This needs to be fixed later.
        response = get(
            url,
            params=params,
            headers=headers,
            verify=False
        )
        # Checking to see if the request was successful
        try:
            response.raise_for_status()
        except HTTPError:
            self.log_me.exception(
                """Request to Q-Radar log source API ended in non-200
                response."""
                )
        # Parsing the JSON response
        data = response.json()
        for entry in data:
            source_list.append(entry['name'])
        return source_list

    def get_siem_source_ex(self, log_source_list):
        """This method is a list comparison that generates a list of
        Windows servers that are not present in log_source_list.

        Required Input:
        log_source_list - list(), A list of hostnames that are sending
        logs to a SIEM.

        Output:
        self.no_log_servers is updated and can be referenced to obtain
        the results of this method.

        Exceptions:
        None."""
        # Basic list content check.
        for server in self.server_list:
            if str(server).strip('$') not in log_source_list:
                self.no_log_servers.append(str(server.strip('$')))
