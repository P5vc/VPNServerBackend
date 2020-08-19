############## WireGuard Support Functions ##############

# Return a list of the first 2000 subnets-worth of valid, WireGuard IP objects:
def wgGetNets(getServerAddresses = False , getNetAddresses = False):
	clientAddresses = []
	serverAddresses = []
	networkAddresses = []

	baseNet = ipaddress.IPv4Network('172.16.0.0/29')

	for i in range(0 , 2000):
		if (i != 0):
			baseNet = ipaddress.IPv4Network(str(baseNet.broadcast_address + 1) + '/' + str(baseNet.netmask))

		networkAddresses.append(str(baseNet))

		tempClientAddressList = []
		for host in list(baseNet.hosts()):
			if (host == list(baseNet.hosts())[0]):
				serverAddresses.append((str(host) + '/29'))
			else:
				tempClientAddressList.append((str(host) + '/32'))
		clientAddresses.append(tempClientAddressList)

	if (getServerAddresses):
		return serverAddresses
	elif (getNetAddresses):
		return networkAddresses
	else:
		return clientAddresses


# Return the next available WireGuard IPs:
def wgAvailIP(wgConfigData):
	serverIPAddresses = []
	serverIPAddressesTemp = wgConfigData['server']['addresses'].split()
	if (len(serverIPAddressesTemp) == 0):
		serverIPAddresses.append('172.16.0.1')
	else:
		for item in serverIPAddressesTemp:
			if ('/29' in item):
				serverIPAddresses.append(item[:(len(item) - 3)])

	index = 0
	for address in wgGetNets(getServerAddresses = True):
		if (not(address[:(len(address) - 3)] in serverIPAddresses)):
			return address , wgGetNets()[index]
		index += 1

############## End of WireGuard Support Functions ##############



################# Shadowsocks Support Functions #################
# Generate random, secure, long, user passwords:
def ssGenPass(length = 50):
	charOptions = (string.ascii_letters + string.digits)
	choices = []
	for i in range(0 , length):
		choices.append(secrets.choice(charOptions))

	return ''.join(choices)


# Return the next two available ports:
def ssAvailPorts(ssConfigData):
	takenPorts = []

	for user in ssConfigData:
		takenPorts.append(ssConfigData[user]['standardPort'])
		takenPorts.append(ssConfigData[user]['pluginPort'])

	portOne = False
	portTwo = False
	for i in range(SHADOWSOCKS_BASE_PORT , 65536):
		if (portOne and portTwo):
			return portOne , portTwo
		if (not(i in takenPorts)):
			if (portOne):
				portTwo = i
			else:
				portOne = i

############## End of Shadowsocks Support Functions ##############



################ General/Mixed Support Functions ################
############# End of General/Mixed Support Functions #############
