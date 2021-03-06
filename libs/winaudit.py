from logging import getLogger
from time import time
from re import search
from configparser import ConfigParser

from ldap import initialize, SCOPE_SUBTREE
from ldap import SERVER_DOWN, INVALID_CREDENTIALS, SIZELIMIT_EXCEEDED
from win32.win32net import NetLocalGroupGetMembers as NLGGM


class ADAudit():
    def __init__(self):
        """An active directory audit object.

        Attributes:
        self.host_list = list(), a list of Windows Servers to audit.
        self.domain_admin_ex = list(),a list objects containing the
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
        self.host_list = []
        self.domain_admin_ex = []
        self.domain_admins = []
        self.log_me = getLogger('WinAudit_Log')
        self.config_file = 'Example.conf'
        self.config = ConfigParser()
        self.config.read(self.config_file)

    def get_servers(self, ldap_dict, sever_ous):
        """Returns a list of servers in specific OUs.

        Inputs:
        ldap_dict - dict(), a dictionary containing the following keys:
        ldap_url, bind_dn, bind_pwd
        server_ous - list(), a list of server OUs.  We will iterate
        throug this list to obtain all servers in a given OU.

        Outputs:
        server_list = self.host_list, a list of servers in server_ous.

        Rasies:
        SERVER_DOWN - Fatal exception that is raised when the LDAP
        server passed in the ldap_dict is not reachable.
        INVALID_CREDENTIALS - Fatal exception that is raised when the
        credentials provided in ldap_dict do not log on.
        SIZELIMIT_EXCEEDED - The returned results of a search are
        greater that the LDAP server's max size limit."""
        # Connecting to LDAP server (i.e., a domain controller)
        ldap_obj = initialize(ldap_dict['ldap_url'])
        start = time()
        try:
            ldap_obj.simple_bind_s(
                ldap_dict['bind_dn'], ldap_dict['bind_pwd']
            )
        # Some exception handling.
        except INVALID_CREDENTIALS:
            self.log_me.exception(
                'Login failure when attempting to connect to: %s',
                ldap_dict['ldap_url']
            )
            exit(1)
        except SERVER_DOWN:
            self.log_me.exception(
                'Cannot contact server at: %s' % ldap_dict['ldap_url']
            )
            exit(1)
        self.log_me.debug(
            'Successfully connected to %s' % ldap_dict['ldap_url']
        )
        # Iterating through OUs, appending the servers in those OUs to
        # the host list.
        for ou in sever_ous:
            try:
                server_data = (
                    ldap_obj.search_s(
                        ou, SCOPE_SUBTREE, 'sAMAccountName=*', ['name'],
                        attrsonly=0
                    )
                )
                self.log_me.debug(
                    'Server members of %s succsefully retrieved' % ou
                )
                for server in server_data:
                    self.host_list.append(
                        server[1].get('name')[0].decode(encoding='ascii')
                    )
                self.log_me.debug(
                    'Server members of %s added to host list.' % ou
                )
            # Some exception handling.
            except SIZELIMIT_EXCEEDED:
                self.log_me.exception(
                    'Size limit exceeded reached when searhcing: %s' % ou
                )
        # Unbinding LDAP object to free up resources.
        ldap_obj.unbind_s()
        end = time()
        _elapsed = end - start
        elapsed = int(round(_elapsed, 0))
        self.log_me.debug('It took %d seconds to retrieve servers' % elapsed)
        self.log_me.info(
            '%d servers added to audit population.' % len(self.host_list)
        )
        # Checking the host list to make sure that it has a reasonable
        # population.
        if len(self.host_list) < 20:
            self.log_me.error(
                'Server list only contains %d members.' % len(self.host_list)
            )

    def get_domain_admins(self, ldap_dict, adm_dn):
        """Returns all members in the domain admin group.

        Input:
        ldap_dict - dict(), A dictionary containing the following keys:
        ldap_url, bind_dn, bind_pwd
        adm_dn, str(), The string (for the admin groups) to search for.


        Output:
        domain_admins - list(), A list of all members in the domain
        admin group.

        Raises:
        SERVER_DOWN - Fatal exception that is raised when the LDAP
        server passed in the ldap_dict is not reachable.
        INVALID_CREDENTIALS - Fatal exception that is raised when the
        credentials provided in ldap_dict do not log on."""
        # Connecting to LDAP server (i.e., a domain controller)
        ldap_obj = initialize(ldap_dict['ldap_url'])
        start = time()
        try:
            ldap_obj.simple_bind_s(
                ldap_dict['bind_dn'], ldap_dict['bind_pwd']
            )
        # Some exception handling.
        except INVALID_CREDENTIALS:
            self.log_me.exception(
                'Login failure when attempting to connect to: %s' %
                (ldap_dict['ldap_url'])
            )
            exit(1)
        except SERVER_DOWN:
            self.log_me.exception(
                'Cannot contact server at: %s' % ldap_dict['ldap_url']
            )
            exit(1)
        self.log_me.debug(
            'Successfully connected to %s' % ldap_dict['ldap_url']
        )
        # Obtaining a list of domain admins.
        self.log_me.debug('Obtaining a list of domain admins.')
        admins = ldap_obj.search_s(
            adm_dn, SCOPE_SUBTREE, 'name=Domain Admins', ['member'],
            attrsonly=0
        )
        # Unbinding LDAP object to free up resources.
        ldap_obj.unbind_s()
        # Iterating through the list of domain admins, and parsing out
        # the common name of the domain admin.  Appending that name
        # to the self.domain_admin attribute.
        for admin in admins[0][1]['member']:
            admin = admin.decode(encoding='ascii')
            admin_name = search(r'(CN=)(\w+)(,OU=.+)', admin)
            if admin_name:
                self.domain_admins.append(admin_name.group(2))
        end = time()
        self.log_me.info('Domain admin list successfully generated.')
        _elapsed = end - start
        elapsed = int(round(_elapsed, 0))
        self.log_me.debug('Domain admins retrieved in %d seconds' % elapsed)

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

        Methods:
        get_local_admins - Gets all of the local administrators from the
        parent attribute of host list.
        get_admin_ex - Generates a list of user accounts that are not
        authorized to have local admin rights."""
        ADAudit.__init__(self)
        self.local_admins = []
        self.local_admin_ex = []
        self.unreachable_servers = []
        self.reachable_servers = []

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
        for server in self.host_list:
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
