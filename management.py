from string import ascii_letters , digits
from sys import argv
from pathlib import Path
from subprocess import call as run
from pickle import dump , load
from secrets import choice
from ipaddress import IPv4Network , IPv4Address



####################### Constants #######################
SERVER_ADDRESS = argv[1]

WG_PORT = 3270
SHADOWSOCKS_BASE_PORT = 3271 # Must be significantly less than 65535
################### End of Constants ###################



################# Values of Significance #################
wgConfigData = {
				'server' : {
							'header' : ['[Interface]\n' , '[Peer]\n'],
							'comment' : '# Server Config\n',
							'addresses' : 'Address = 172.16.0.1/29',
							'port' : ('ListenPort = ' + str(WG_PORT) + '\n'),
							'privateKey' : 'PrivateKey = gEPppkv0UpouXV1eMkRe7TasdU642Eixna4p2FB0xX4=\n',
							'publicKey' : 'PublicKey = AP49cli8mTh7B4KDJYGQlXDGa+ohvqmFZTR1A/wg0j8=\n',
							'saveConfig' : 'SaveConfig = false\n',
							'allowedIPs' : 'AllowedIPs = 0.0.0.0/0, ::/0\n',
							'endpoint' : ('Endpoint = ' + SERVER_ADDRESS + ':' + str(WG_PORT) + '\n')
							}
				}

ssConfigData = {
				'defaultUser' : {
								'standardPort' : SHADOWSOCKS_BASE_PORT,
								'pluginPort' : (SHADOWSOCKS_BASE_PORT + 1),
								'standardPassword' : '7Gjll72mDRP9qQLGRWzdjsGmca1L2sHYTM9FAfXAlLks5H7UCQ',
								'pluginPassword' : 'ioGDXCxHAVPTvXsFWRQjavL44qgrANKKWqyPgmG9sGJQMZaUpd'
								}
				}
############## End of Values of Significance ##############



############## WireGuard Support Functions ##############
# Return a list of the first 2000 subnets-worth of valid, WireGuard IP objects:
def wgGetNets(getServerAddresses = False , getNetAddresses = False):
	clientAddresses = []
	serverAddresses = []
	networkAddresses = []

	baseNet = IPv4Network('172.16.0.0/29')

	for i in range(0 , 2000):
		if (i != 0):
			baseNet = IPv4Network(str(baseNet.broadcast_address + 1) + '/' + str(baseNet.netmask))

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


# Generate and return WireGuard private key/public key pairs, or a pre-shared key:
def wgGenKeys(genPSK = False):
	if (genPSK):
		run('wg genpsk | tee /etc/wireguard/psk' , shell = True)

		psk = ''
		with open('/etc/wireguard/psk' , 'r') as pskFile:
			psk = pskFile.read().strip()

		Path('/etc/wireguard/psk').unlink(missing_ok = True)

		return psk
	else:
		run('wg genkey | tee /etc/wireguard/privKey | wg pubkey | tee /etc/wireguard/pubKey' , shell = True)

		privKey = ''
		with open('/etc/wireguard/privKey' , 'r') as privKeyFile:
			privKey = privKeyFile.read().strip()
		pubKey = ''
		with open('/etc/wireguard/pubKey' , 'r') as pubKeyFile:
			pubKey = pubKeyFile.read().strip()

		Path('/etc/wireguard/privKey').unlink(missing_ok = True)
		Path('/etc/wireguard/pubKey').unlink(missing_ok = True)

		return privKey , pubKey


# Handle WireGuard config data:
def wgConfigDataHandler(data = False):
	if (data):
		with open('/root/WireGuardConfigData.dat' , 'wb') as wgConfigDataFile:
			dump(data , wgConfigDataFile)
	else:
		with open('/root/WireGuardConfigData.dat' , 'rb') as wgConfigDataFile:
			return load(wgConfigDataFile)


# Write WireGuard config file and restart the interface:
def wgRefresh():
	wgConfigData = wgConfigDataHandler()
	wgConfigString = ''

	# Add server config data:
	wgConfigString += (wgConfigData['server']['header'][0] + wgConfigData['server']['comment'] + wgConfigData['server']['addresses'] + wgConfigData['server']['port'] + wgConfigData['server']['privateKey'] + wgConfigData['server']['saveConfig'] + '\n\n')

	# Add user config data:
	for user in wgConfigData.keys():
		if (user == 'server'):
			continue
		for userNum in range(0 , 5):
			wgConfigString += (wgConfigData[user][userNum]['header'][0] + wgConfigData[user][userNum]['comment'] + wgConfigData[user][userNum]['publicKey'] + wgConfigData[user][userNum]['psk'] + wgConfigData[user][userNum]['allowedIPs'] + '\n')

	with open('/etc/wireguard/wg0.conf' , 'w') as wgIntFile:
		wgIntFile.write(wgConfigString)

	run('chmod -R 600 /etc/wireguard/' , shell = True)

	run('ip link del dev wg0' , shell = True)
	run('wg-quick up wg0' , shell = True)

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
	charOptions = (ascii_letters + digits)
	choices = []
	for i in range(0 , length):
		choices.append(choice(charOptions))

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



################# Daily Update/Maintenance Tasks #################
# Check if the initial user configuration files exist and create them if not:
if ((not(Path('/root/WireGuardConfigData.dat').is_file())) or (not(Path('/root/ShadowsocksConfigData.dat').is_file()))):
	serverAddresses = wgGetNets(getServerAddresses = True)[0]
	configServerAddresses = ('Address = ' + serverAddresses + '\n')

	serverPrivKey , serverPubKey = wgGenKeys()

	# Save a default WireGuard configuration:
	wgConfigData = {'server' : {'header' : ['[Interface]\n' , '[Peer]\n'] , 'comment' : '# Server Config\n' , 'addresses' : configServerAddresses , 'port' : ('ListenPort = ' + str(WG_PORT) + '\n') , 'privateKey' : ('PrivateKey = ' + serverPrivKey + '\n') , 'publicKey' : ('PublicKey = ' + serverPubKey + '\n') , 'saveConfig' : 'SaveConfig = false\n' , 'allowedIPs' : 'AllowedIPs = 0.0.0.0/0, ::/0\n' , 'endpoint' : ('Endpoint = ' + SERVER_ADDRESS + ':' + str(WG_PORT) + '\n')}}

	wgConfigDataHandler(wgConfigData)

	wgRefresh()

	# Enable WireGuard:
	run('systemctl enable wg-quick@wg0.service' , shell = True)

	# Disable shadowsocks:
	run('systemctl disable shadowsocks-libev.service' , shell = True)

	# Save a default Shadowsocks user configuration:
	ssConfigDataHandler({'defaultUser' : {'standardPort' : SHADOWSOCKS_BASE_PORT , 'pluginPort' : (SHADOWSOCKS_BASE_PORT + 1) , 'standardPassword' : ssGenPass() , 'pluginPassword' : ssGenPass()}})
############## End of Daily Update/Maintenance Tasks ##############
