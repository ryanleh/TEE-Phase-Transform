import logging
try:
    import _winreg
except ImportError, e:
    logging.error('error importing winreq')
import os
from socket import gethostbyname
from ai_utils.phases.abstract_phase import AbstractPhaseClass

REG_PATH_1 = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
REG_PATH_2 = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'
DNS_SERVER = '8.8.8.8'

class DnsChangerPhaseClass(AbstractPhaseClass):
    TrackerId = "141"
    Subject = "Change NameServer"
    Description = "Tries to change client dns"

    def __init__(self, isPhaseCritical):
        AbstractPhaseClass.__init__(self, isPhaseCritical)
        self.InitialInternetConnectionSuccessful = False

    def GetDnsRegistryNameserver(self, reg_path_to_parameters):
        self.PhaseReporter.Info('Getting DNS registry nameserver at {0}'.format(reg_path_to_parameters))
        nameserver = self.GetDnsRegistryValue(reg_path_to_parameters, 'NameServer')
        logging.info('DNS registry nameserver: {0}'.format(nameserver))
        return nameserver

    def SetDnsRegistryNameserver(self, old_nameserver, new_nameserver, reg_path_to_parameters):
        self.PhaseReporter.Info('Setting DNS registry nameserver {0} to {1} at {2}'.format(old_nameserver, new_nameserver, reg_path_to_parameters))
        return self.SetDnsRegistryValue(reg_path_to_parameters, 'NameServer', new_nameserver)

    def GetDnsRegistryDhcpNameserver(self, reg_path_to_parameters):
        self.PhaseReporter.Info('Getting DNS registry DHCP nameserver at {0}'.format(reg_path_to_parameters))
        dhcp_nameserver = self.GetDnsRegistryValue(reg_path_to_parameters, 'DhcpNameServer')
        logging.info('DNS registry DHCP Nameserver: {0}'.format(dhcp_nameserver))
        return dhcp_nameserver

    def SetDnsResitryDhcpNameserver(self, old_dhcp_nameserver, new_dhcp_nameserver, reg_path_to_parameters):
        self.PhaseReporter.Info('Setting DNS registry DHCP nameserver {0} to {1} at {2}'.format(old_dhcp_nameserver, new_dhcp_nameserver, reg_path_to_parameters))
        return self.SetDnsRegistryValue(reg_path_to_parameters, 'DhcpNameServer', new_dhcp_nameserver)

    def GetDnsRegistryInterfaceNameservers(self, interfaces, reg_path_to_interfaces):
        self.PhaseReporter.Info('Getting DNS registry nameservers for {0}'.format(interfaces))
        nameservers = []
        for interface in interfaces:
            nameservers.append(self.GetDnsRegistryValue(reg_path_to_interfaces + '\\' + interface, 'NameServer'))
        logging.info('NameServers for interfaces: {0}'.format(nameservers))
        return nameservers

    def SetDnsRegistryInterfaceNameservers(self, interfaces, old_interface_nameservers, new_interface_nameserver, reg_path_to_interfaces):
        self.PhaseReporter.Info('Setting DNS registry nameservers for interfaces to {0}'.format(new_interface_nameserver))
        interfaceIndex = 0
        failureCount = 0
        for interface in interfaces:
            if old_interface_nameservers[interfaceIndex] is not None:
                if not self.SetDnsRegistryValue(reg_path_to_interfaces + '\\' + interface, 'NameServer', new_interface_nameserver):
                    failureCount += 1
            interfaceIndex += 1
        logging.info('Finished setting DNS registry nameservers for interfaces to {0}'.format(new_interface_nameserver))
        return failureCount == 0

    def ResetDnsRegistryInterfaceNameservers(self, interfaces, interface_nameservers, reg_path_to_interfaces):
        self.PhaseReporter.Info('Resetting DNS registry interface nameservers...')
        interfaceIndex = 0
        failureCount = 0
        for interface in interfaces:
            if interface_nameservers[interfaceIndex] is not None:
                if not self.SetDnsRegistryValue(reg_path_to_interfaces + '\\' + interface, 'NameServer', interface_nameservers[interfaceIndex]):
                    failureCount += 1
            interfaceIndex += 1
        logging.info('Finished resetting DNS registry interface nameservers')
        return failureCount == 0

    def GetDnsRegistryInterfaceDhcpNameservers(self, interfaces, reg_path_to_interfaces):
        self.PhaseReporter.Info('Getting DNS registry DHCP nameservers for {0}'.format(interfaces))
        dhcp_nameservers = []
        for interface in interfaces:
            dhcp_nameservers.append(self.GetDnsRegistryValue(reg_path_to_interfaces + '\\' + interface, 'DhcpNameServer'))
        logging.info('DHCP NameServers for interfaces: {0}'.format(dhcp_nameservers))
        return dhcp_nameservers

    def SetDnsRegistryInterfaceDhcpNameservers(self, interfaces, old_interface_dhcp_nameservers, new_interface_dhcp_nameserver, reg_path_to_interfaces):
        self.PhaseReporter.Info('Setting DNS registry DHCP nameservers for interfaces to {0}'.format(new_interface_dhcp_nameserver))
        interfaceIndex = 0
        failureCount = 0
        for interface in interfaces:
            if old_interface_dhcp_nameservers[interfaceIndex] is not None:
                if not self.SetDnsRegistryValue(reg_path_to_interfaces + '\\' + interface, 'DhcpNameServer', new_interface_dhcp_nameserver):
                    failureCount += 1
            interfaceIndex += 1
        logging.info('Finished setting DNS registry DHCP nameservers for interfaces to {0}'.format(new_interface_dhcp_nameserver))
        return failureCount == 0

    def ResetDnsRegistryInterfaceDhcpNameservers(self, interfaces, interface_dhcp_nameservers, reg_path_to_interfaces):
        self.PhaseReporter.Info('Resetting DNS registry interface DHCP nameservers')
        interfaceIndex = 0
        failureCount = 0
        for interface in interfaces:
            if interface_dhcp_nameservers[interfaceIndex] is not None:
                if not self.SetDnsRegistryValue(reg_path_to_interfaces + '\\' + interface, 'DhcpNameServer', interface_dhcp_nameservers[interfaceIndex]):
                    failureCount += 1
            interfaceIndex += 1
        logging.info('Finished resetting DNS registry interface DHCP nameservers')
        return failureCount == 0

    @staticmethod
    def GetDnsRegistryValue(reg_path, item):
        logging.info('Getting DNS registry value - reg_path: {0}, item: {1}'.format(reg_path, item))
        try:
            registry_key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, reg_path, 0, _winreg.KEY_READ)
            value, regtype = _winreg.QueryValueEx(registry_key, item)
            _winreg.CloseKey(registry_key)
            logging.info('Retrieved DNS registry value: {0} - reg_path: {1}, item: {2}'.format(value, reg_path, item))
            return value
        except WindowsError:
            logging.info('Error while getting DNS registry key - reg_path: {0}, item: {1}'.format(reg_path, item))
            return None

    @staticmethod
    def SetDnsRegistryValue(reg_path, item, value):
        logging.info('Setting DNS registry key - reg_path: {0}, item: {1}, value:{2}'.format(reg_path, item, value))
        try:
            _winreg.CreateKey(_winreg.HKEY_LOCAL_MACHINE, reg_path)
            registry_key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, reg_path, 0, _winreg.KEY_WRITE)
            _winreg.SetValueEx(registry_key, item, 0, _winreg.REG_SZ, value)
            _winreg.CloseKey(registry_key)
            logging.info('DNS registry key set - reg_path: {0}, item: {1}, value:{2}'.format(reg_path, item, value))
            return True
        except WindowsError:
            logging.info('Error while setting DNS registry key - reg_path: {0}, item: {1}, value:{2}'.format(reg_path, item, value))
            return False

    @staticmethod
    def GetInterfaces(reg_path):
        logging.info('Getting interfaces at reg_path {0}'.format(reg_path))
        interfaces = []
        count = 0
        registry_key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, reg_path, 0, _winreg.KEY_READ)
        while True:
            try:
                interface = _winreg.EnumKey(registry_key, count)
                interfaces.append(interface)
                count += 1
            except WindowsError:
                logging.info('Total interfaces: {0}'.format(count))
                break
        logging.info('Interfaces found: {0}'.format(interfaces))
        return interfaces

    def GetOriginalDnsSettings(self):
        self.PhaseReporter.Info('Getting original DNS registry settings...')
        self.interfaces = self.GetInterfaces(REG_PATH_2)
        self.original_nameserver = self.GetDnsRegistryNameserver(REG_PATH_1)
        self.original_dhcp_nameserver = self.GetDnsRegistryDhcpNameserver(REG_PATH_1)
        self.original_interface_nameservers = self.GetDnsRegistryInterfaceNameservers(self.interfaces, REG_PATH_2)
        self.original_interface_dhcp_nameservers = self.GetDnsRegistryInterfaceDhcpNameservers(self.interfaces, REG_PATH_2)

    def SetNewDnsSettings(self):
        self.PhaseReporter.Info('Setting new DNS registry settings...')
        s1 = self.SetDnsRegistryNameserver(self.original_nameserver, DNS_SERVER, REG_PATH_1)
        s2 = self.SetDnsResitryDhcpNameserver(self.original_dhcp_nameserver, DNS_SERVER, REG_PATH_1)
        s3 = self.SetDnsRegistryInterfaceNameservers(self.interfaces, self.original_interface_nameservers, DNS_SERVER, REG_PATH_2)
        s4 = self.SetDnsRegistryInterfaceDhcpNameservers(self.interfaces, self.original_interface_dhcp_nameservers, DNS_SERVER, REG_PATH_2)
        return s1 and s2 and s3 and s4

    def RevertToOriginalDnsSettings(self):
        self.PhaseReporter.Info('Resetting DNS registry settings back to original values...')
        s1 = self.SetDnsRegistryNameserver(DNS_SERVER, self.original_nameserver, REG_PATH_1)
        s2 = self.SetDnsResitryDhcpNameserver(DNS_SERVER, self.original_dhcp_nameserver, REG_PATH_1)
        s3 = self.ResetDnsRegistryInterfaceNameservers(self.interfaces, self.original_interface_nameservers, REG_PATH_2)
        s4 = self.ResetDnsRegistryInterfaceDhcpNameservers(self.interfaces, self.original_interface_dhcp_nameservers, REG_PATH_2)
        return s1 and s2 and s3 and s4

    def TestDns(self):
        domain_name = 'google.com'
        logging.info('Checking DNS for {0} to verify DNS settings'.format(domain_name))
        try:
            os.system('ipconfig /flushdns')
            os.system('net stop dnscache')
            ipaddress = gethostbyname(domain_name)
            os.system('net start dnscache')
            self.PhaseReporter.Info('DNS settings verified. IP address found {0} for domain {1}'.format(ipaddress, domain_name))
            return True
        except:
            self.PhaseReporter.Info('DNS settings not verified. Domain name ({0}) could not be reached'.format(domain_name))
            return False

    def ChangeDns(self):
        self.InitialInternetConnectionSuccessful = self.TestDns()
        self.GetOriginalDnsSettings()
        phaseSuccess = self.SetNewDnsSettings() and self.TestDns() == self.InitialInternetConnectionSuccessful
        return phaseSuccess

    def Cleanup(self):
        if not self.RevertToOriginalDnsSettings():
            self.PhaseReporter.Error('Previous DNS settings could not be set.')
            self._PrintErrorWhenRestoringPreviousDNSSettings()
        if not self.TestDns() and self.InitialInternetConnectionSuccessful:
            self.PhaseReporter.Warn('With previous DNS settings, there was internet connection. After restoring settings, there was not')
            self._PrintErrorWhenRestoringPreviousDNSSettings()

    def _PrintErrorWhenRestoringPreviousDNSSettings(self):
        self.PhaseReporter.Info('Check the following registry keys: {0}, {1}'.format(REG_PATH_1, REG_PATH_2))
        self.PhaseReporter.Info('Previous DNS values: Nameservers:{0}, DHCP Nameservers:{1}, Interface Nameservers:{2}, '
                                'Interface DHCP Nameservers: {3}'.format(self.original_nameserver,
                                                                         self.original_dhcp_nameserver,
                                                                         self.original_interface_nameservers,
                                                                         self.original_interface_dhcp_nameservers))

    def Run(self):
        phaseSuccessful = self.ChangeDns()
        if phaseSuccessful:
            self.PhaseReporter.Info('Successfully changed DNS settings')
            self.PhaseReporter.Report('Your security controls failed because the registry entries used to set up the network configuration could be changed.')
        else:
            self.PhaseReporter.Info('Failed to change DNS settings')
        return phaseSuccessful
