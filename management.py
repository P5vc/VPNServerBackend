from string import ascii_letters , digits
from base64 import b64encode
from uuid import uuid4
from sys import argv
from pathlib import Path
from shutil import rmtree
from subprocess import call as run
from pickle import dump , load
from secrets import choice
from ipaddress import IPv4Network , IPv4Address



####################### Constants #######################
SERVER_ADDRESS = argv[1]
SERVER_ID = argv[2]

NETWORK_INTERFACE = argv[3]

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


# Write WireGuard config file and restart the interface:
def wgRefresh():
	wgConfigData = configDataHandler('WireGuard')
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


# Return the next available WireGuard IP block:
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


# Create WireGuard client configuration files:
def wgGenClientConfigs():
	rmtree('/root/configs/WireGuard')
	Path('/root/configs/WireGuard').mkdir()

	wgConfigData = configDataHandler('WireGuard')

	for user in wgConfigData:
		if (user == 'server'):
			continue

		for userNum in range(0 , 5):
			userConfigString = (wgConfigData[user][userNum]['header'][1] + wgConfigData[user][userNum]['privateKey'] + wgConfigData[user][userNum]['addresses'] + wgConfigData[user][userNum]['dns'] + '\n' + wgConfigData['server']['header'][1] + wgConfigData['server']['publicKey'] + wgConfigData[user][userNum]['psk'] + 'AllowedIPs = 0.0.0.0/0, ::/0\n' + wgConfigData['server']['endpoint'])

			with open(('/root/configs/WireGuard/' + user + '-' + str(userNum + 1) + '.conf') , 'w') as userConfigFile:
				userConfigFile.write(userConfigString)

			configUUID = str(uuid4()).upper()

			### Start of Custom Apple Device Configuration Profile ###
			mobileConfigFileString = '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n<dict>\n\t<key>PayloadContent</key>\n\t<array>\n<dict>\n\t<key>IPv4</key>\n<dict>\n\t<key>OverridePrimary</key>\n\t<integer>1</integer>\n</dict>\n\t<key>PayloadDescription</key>\n\t<string>Configures VPN settings</string>\n\t<key>PayloadDisplayName</key>\n\t<string>PriveasyVPN</string>\n\t<key>PayloadIdentifier</key>\n'
			mobileConfigFileString += ('\t<string>com.apple.vpn.managed.PriveasyVPN' + configUUID + '</string>\n')
			mobileConfigFileString += '\t<key>PayloadType</key>\n\t<string>com.apple.vpn.managed</string>\n\t<key>PayloadUUID</key>\n'
			mobileConfigFileString += ('\t<string>PriveasyVPN' + configUUID + '</string>\n')
			mobileConfigFileString += '\t<key>PayloadVersion</key>\n\t<integer>1</integer>\n\t<key>Proxies</key>\n\t<dict>\n\t\t<key>HTTPEnable</key>\n\t\t<integer>0</integer>\n\t\t<key>HTTPSEnable</key>\n\t\t<integer>0</integer>\n\t</dict>\n\t<key>UserDefinedName</key>\n\t<string>Priveasy VPN</string>\n\t<key>VPN</key>\n\t<dict>\n<key>OnDemandEnabled</key>\n<integer>1</integer>\n<key>OnDemandRules</key>\n<array>\n<dict>\n\t<key>Action</key>\n\t<string>Connect</string>\n\t<key>InterfaceTypeMatch</key>\n\t<string>WiFi</string>\n\t<key>URLStringProbe</key>\n\t<string>http://captive.apple.com/hotspot-detect.html</string>\n</dict>\n<dict>\n\t<key>Action</key>\n\t<string>Connect</string>\n\t<key>InterfaceTypeMatch</key>\n\t<string>Cellular</string>\n\t<key>URLStringProbe</key>\n\t<string>http://captive.apple.com/hotspot-detect.html</string>\n</dict>\n<dict>\n\t<key>Action</key>\n\t<string>Disconnect</string>\n</dict>\n</array>\n<key>AuthenticationMethod</key>\n<string>Password</string>\n<key>RemoteAddress</key>\n'
			mobileConfigFileString += ('<string>' + SERVER_ADDRESS + ':' + str(WG_PORT) + '</string>\n')
			mobileConfigFileString += '</dict>\n<key>VPNSubType</key>\n<string>com.wireguard.ios</string>\n<key>VPNType</key>\n<string>VPN</string>\n<key>VendorConfig</key>\n<dict>\n\t<key>WgQuickConfig</key>\n\t<string>[Interface]\n'
			mobileConfigFileString += ('\t' + wgConfigData[user][userNum]['privateKey'])
			mobileConfigFileString += ('\t' + wgConfigData[user][userNum]['addresses'])
			mobileConfigFileString += ('\t' + wgConfigData[user][userNum]['dns'])
			mobileConfigFileString += ('\n\t' + wgConfigData['server']['header'][1])
			mobileConfigFileString += ('\t' + wgConfigData['server']['publicKey'])
			mobileConfigFileString += ('\t' + wgConfigData[user][userNum]['psk'])
			mobileConfigFileString += '\tAllowedIPs = 0.0.0.0/0, ::/0\n'
			mobileConfigFileString += ('\t' + wgConfigData['server']['endpoint'])
			mobileConfigFileString += '</string>\n</dict>\n</dict>  </array>\n<key>PayloadDisplayName</key>\n<string>Priveasy VPN</string>\n<key>PayloadIdentifier</key>\n'
			mobileConfigFileString += ('<string>donut.local.' + str(uuid4()).upper() + '</string>\n')
			mobileConfigFileString += '<key>PayloadOrganization</key>\n<string>PriveasyVPN</string>\n<key>PayloadRemovalDisallowed</key>\n<false/>\n<key>PayloadType</key>\n<string>Configuration</string>\n<key>PayloadUUID</key>\n'
			mobileConfigFileString += ('<string>' + str(uuid4()).upper() + '</string>\n')
			mobileConfigFileString += '<key>PayloadVersion</key>\n<integer>1</integer>\n</dict>\n</plist>\n'
			### End of Custom Apple Device Configuration Profile ###

			with open(('/root/configs/WireGuard/' + user + '-' + str(userNum + 1) + '.mobileconfig') , 'w') as userConfigFile:
				userConfigFile.write(mobileConfigFileString)
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


# Update shadowsocks server configs, and start the correct processes at boot:
def ssRefresh():
	# Clear old configs:
	rmtree('/etc/shadowsocks-libev')
	Path('/etc/shadowsocks-libev').mkdir()
	# Create PID directory:
	Path('/etc/shadowsocks-libev/PIDs').mkdir()

	ssConfigData = configDataHandler('Shadowsocks')

	for user in ssConfigData:
		with open('/etc/shadowsocks-libev/' + user + '-standard.json' , 'w') as userConfigFile:
			userConfigFile.write('{\n    "server":["' + SERVER_ADDRESS + '"],\n    "mode":"tcp_and_udp",\n    "server_port":' + str(ssConfigData[user]['standardPort']) + ',\n    "local_port":1080,\n    "password":"' + ssConfigData[user]['standardPassword'] + '",\n    "timeout":60,\n    "method":"chacha20-ietf-poly1305",\n    "fast_open":true,\n    "acl":"/root/server_block_local.acl",\n}')
		with open('/etc/shadowsocks-libev/' + user + '-plugin.json' , 'w') as userConfigFile:
			userConfigFile.write('{\n    "server":["' + SERVER_ADDRESS + '"],\n    "mode":"tcp_and_udp",\n    "server_port":' + str(ssConfigData[user]['pluginPort']) + ',\n    "local_port":1080,\n    "password":"' + ssConfigData[user]['pluginPassword'] + '",\n    "timeout":60,\n    "method":"chacha20-ietf-poly1305",\n    "fast_open":true,\n    "acl":"/root/server_block_local.acl",\n    "plugin":"/root/go/bin/v2ray-plugin",\n    "plugin_opts":"server"\n}')

	cronFileContents = ''
	with open('/etc/cron.d/priveasy' , 'r') as cronFile:
		for line in cronFile.readlines():
			if ('# Automatically relaunch ss-server processes for each client:' in line):
				cronFileContents += line
				for user in ssConfigData:
					cronFileContents += '@reboot root /usr/bin/ss-server -c /etc/shadowsocks-libev/' + user + '-standard.json -f /etc/shadowsocks-libev/PIDs/' + user + '-standard\n'
					cronFileContents += '@reboot root /usr/bin/ss-server -c /etc/shadowsocks-libev/' + user + '-plugin.json -f /etc/shadowsocks-libev/PIDs/' + user + '-plugin\n'
				break
			else:
				cronFileContents += line

	with open('/etc/cron.d/priveasy' , 'w') as cronFile:
		cronFile.write(cronFileContents)

	# Restart all Shadowsocks server processes:
	run('pkill ss-server' , shell = True)

	for user in ssConfigData:
		run('/usr/bin/ss-server -c /etc/shadowsocks-libev/' + user + '-standard.json -f /etc/shadowsocks-libev/PIDs/' + user + '-standard' , shell = True)
		run('/usr/bin/ss-server -c /etc/shadowsocks-libev/' + user + '-plugin.json -f /etc/shadowsocks-libev/PIDs/' + user + '-plugin' , shell = True)


# Create Shadowsocks client configuration files:
def ssGenClientConfigs():
	rmtree('/root/configs/Shadowsocks')
	Path('/root/configs/Shadowsocks').mkdir()

	ssConfigData = configDataHandler('Shadowsocks')

	for user in ssConfigData:
		standardURL = ('ss://' + str(b64encode(('chacha20-ietf-poly1305:' + ssConfigData[user]['standardPassword'] + '@' + SERVER_ADDRESS + ':' + str(ssConfigData[user]['standardPort'])).encode('utf-8')) , 'utf-8'))

		with open(('/root/configs/Shadowsocks/' + user + '.conf') , 'w') as userConfigFile:
			userConfigFile.write('Shadowsocks Connection Information:\n\n\nStandard Connection:\n\nServer IP:\t\t' + SERVER_ADDRESS + '\nServer Port:\t\t' + str(ssConfigData[user]['standardPort']) + '\nPassword:\t\t' + str(ssConfigData[user]['standardPassword']) + '\nEncryption Method:\tchacha20-ietf-poly1305\nRecommended Local Port:\t1080\n\nOutline Client Configuration URL:\n' + standardURL + '\n\nClient Command to Start Shadowsocks SOCKS5 Proxy:\nss-local -s ' + SERVER_ADDRESS + ' -p ' + str(ssConfigData[user]['standardPort']) + ' -l 1080 -k ' + str(ssConfigData[user]['standardPassword']) + ' -m chacha20-ietf-poly1305\n\n\nObfuscated Connection:\n\nServer IP:\t\t' + SERVER_ADDRESS + '\nServer Port:\t\t' + str(ssConfigData[user]['pluginPort']) + '\nPassword:\t\t' + str(ssConfigData[user]['pluginPassword']) + '\nEncryption Method:\tchacha20-ietf-poly1305\nPlugin Program:\t\tv2ray-plugin\nPlugin Options:\t\tclient\nRecommended Local Port:\t1080\n')
############## End of Shadowsocks Support Functions ##############



################ General/Mixed Support Functions ################
# Handle configuration data:
def configDataHandler(application , data = False):
	savedData = {}
	pUsersData = {}
	if (Path('/root/configData.dat').exists()):
		with open('/root/configData.dat' , 'rb') as configDataFile:
			savedData = load(configDataFile)
	else:
		with open('/root/pUsers.dat' , 'rb') as persistentConfigDataFile:
			pUsersData = load(persistentConfigDataFile)
		with open('/root/configData.dat' , 'wb') as configDataFile:
			dump(pUsersData , configDataFile)


	with open('/root/pUsers.dat' , 'rb') as persistentConfigDataFile:
		pUsersData = load(persistentConfigDataFile)


	if (data):
		for user in data:
			if (user in pUsers):
				pUsersData[application][user] = data[user]
			else:
				if (user in pUsersData[application]):
					pUsersData[application].remove(user)

		savedData[application] = data

		with open('/root/pUsers.dat' , 'wb') as persistentConfigDataFile:
			dump(pUsersData , persistentConfigDataFile)
		with open('/root/configData.dat' , 'wb') as configDataFile:
			dump(savedData , configDataFile)
	else:
		return savedData[application]


# Update ufw rules:
def ufwUpdate():
	# Get a list of the network addresses being used:
	usedNetAddresses = []

	wgConfigData = configDataHandler('WireGuard')

	serverIPAddresses = []
	serverIPAddressesTemp = wgConfigData['server']['addresses'].split()
	for item in serverIPAddressesTemp:
		if ('172.16.' in item):
			serverIPAddresses.append(IPv4Network(item[:len(item) - 3] + '/32'))
	for serverIP in serverIPAddresses:
		for netAddr in wgGetNets(getNetAddresses = True):
			netAddr = IPv4Network(netAddr)
			if (netAddr.overlaps(serverIP)):
				usedNetAddresses.append(str(netAddr))

	usedNetAddresses.append('169.254.0.0/16')

	# Reset ufw:
	run('yes | ufw reset' , shell = True)
	# Remove rules backups:
	run('rm /etc/ufw/before.rules.* /etc/ufw/after.rules.* /etc/ufw/user.rules.* /etc/ufw/before6.rules.* /etc/ufw/after6.rules.* /etc/ufw/user6.rules.*' , shell = True)

	# Edit the ufw before rules file:
	ufwConfigFileContents = ''
	addedLinesReached = False
	with open('/etc/ufw/before.rules' , 'r') as ufwFile:
		for line in ufwFile.readlines():
			if (addedLinesReached):
				if ('###########################################################################' in line):
					addedLinesReached = False
					continue
				else:
					continue

			if ('################## THESE LINES WERE MODIFIED BY PRIVEASY ##################' in line):
				addedLinesReached = True
			if ('# drop INVALID packets' in line):
				ufwConfigFileContents += ('\n\n################## THESE LINES WERE MODIFIED BY PRIVEASY ##################\n# Accept packets using the encapsulation protocol:\n-A ufw-before-input -p esp -j ACCEPT\n-A ufw-before-input -p ah -j ACCEPT\n\n# Accept DNS traffic to the local DNS resolver (dnscrypt-proxy):\n-A INPUT -d 172.31.253.253 -p udp --dport 53 -j ACCEPT\n\n# Drop traffic between VPN clients:\n')
				for netAddr in usedNetAddresses:
					usedNetAddresses2 = []
					for netAddr2 in usedNetAddresses:
						if (netAddr2 != netAddr):
							usedNetAddresses2.append(netAddr2)
					ufwConfigFileContents += ('-A ufw-before-input -s ' + netAddr + ' -d ' + ','.join(usedNetAddresses2) + ' -j DROP\n')
				ufwConfigFileContents += ('-A ufw-before-input -s ' + '169.254.0.0/16' + ' -d ' + '169.254.0.0/16' + ' -j DROP\n')
				ufwConfigFileContents += ('\n# Drop traffic to the link-local network:\n-A ufw-before-forward -s ' + ','.join(usedNetAddresses) + ' -d 169.254.0.0/16 -j DROP\n\n# Drop SMB/CIFS traffic that requests to be forwarded:\n-A ufw-before-forward -p tcp --dport 445 -j DROP\n\n# Drop NETBIOS trafic that requests to be forwarded:\n-A ufw-before-forward -p udp -m multiport --ports 137,138 -j DROP\n-A ufw-before-forward -p tcp -m multiport --ports 137,139 -j DROP\n\n# Forward any traffic from the WireGuard VPN network:\n-A ufw-before-forward -m conntrack --ctstate NEW -s ' + ','.join(usedNetAddresses) + ' -m policy --pol none --dir in -j ACCEPT\n\n')

				ufwConfigFileContents += '# Limit the number of simultaneous shadowsocks connections per user:\n'

				ssConfigData = configDataHandler('Shadowsocks')

				for user in ssConfigData:
					ufwConfigFileContents += '-A ufw-before-input -p tcp --syn --dport ' + str(ssConfigData[user]['standardPort']) + ' -m connlimit --connlimit-above 3 -j REJECT --reject-with tcp-reset\n'
					ufwConfigFileContents += '-A ufw-before-input -p tcp --syn --dport ' + str(ssConfigData[user]['pluginPort']) + ' -m connlimit --connlimit-above 2 -j REJECT --reject-with tcp-reset\n'

				ufwConfigFileContents += '\n###########################################################################\n\n'
				ufwConfigFileContents += line
				continue
			ufwConfigFileContents += line

	with open('/etc/ufw/before.rules' , 'w') as ufwFile:
		ufwFile.write(ufwConfigFileContents)

	# Append additional rules to the ufw before rules file, to enable NAT:
	with open('/etc/ufw/before.rules' , 'a') as ufwFile:
		ufwFile.write('\n\n\n################## THESE LINES WERE MODIFIED BY PRIVEASY ##################' + '\n*nat\n\n:PREROUTING ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n\n-A POSTROUTING -s ' + ','.join(usedNetAddresses) + ' -o ' + NETWORK_INTERFACE + ' -m policy --pol none --dir out -j MASQUERADE\n\nCOMMIT\n###########################################################################')

	# Enable and configure ufw:
	run('yes | ufw enable && ufw allow ' + str(WG_PORT) , shell = True)

	ssConfigData = configDataHandler('Shadowsocks')
	for user in ssConfigData:
		run('ufw allow ' + str(ssConfigData[user]['standardPort']) , shell = True)
		run('ufw allow ' + str(ssConfigData[user]['pluginPort']) , shell = True)

	run('ufw reload' , shell = True)
############# End of General/Mixed Support Functions #############



################# Daily Update/Maintenance Tasks #################
# Check if the initial user configuration files exist and create them if not:
if (not(Path('/root/configData.dat').is_file())):
	pUsers = []

	serverAddresses = wgGetNets(getServerAddresses = True)[0]
	configServerAddresses = ('Address = ' + serverAddresses + '\n')

	serverPrivKey , serverPubKey = wgGenKeys()

	# Save a default WireGuard configuration:
	wgConfigData = {'server' : {'header' : ['[Interface]\n' , '[Peer]\n'] , 'comment' : '# Server Config\n' , 'addresses' : configServerAddresses , 'port' : ('ListenPort = ' + str(WG_PORT) + '\n') , 'privateKey' : ('PrivateKey = ' + serverPrivKey + '\n') , 'publicKey' : ('PublicKey = ' + serverPubKey + '\n') , 'saveConfig' : 'SaveConfig = false\n' , 'allowedIPs' : 'AllowedIPs = 0.0.0.0/0, ::/0\n' , 'endpoint' : ('Endpoint = ' + SERVER_ADDRESS + ':' + str(WG_PORT) + '\n')}}

	configDataHandler('WireGuard' , wgConfigData)

	wgRefresh()

	# Enable WireGuard:
	run('systemctl enable wg-quick@wg0.service' , shell = True)

	# Disable shadowsocks:
	run('systemctl disable shadowsocks-libev.service' , shell = True)

	# Save a default Shadowsocks user configuration:
	configDataHandler('Shadowsocks' , {'defaultUser' : {'standardPort' : SHADOWSOCKS_BASE_PORT , 'pluginPort' : (SHADOWSOCKS_BASE_PORT + 1) , 'standardPassword' : ssGenPass() , 'pluginPassword' : ssGenPass()}})

	exit()

# Main tasks:
# Create a list of desired user profiles:
users = []
pUsers = []

with open('/root/' + SERVER_ID + '.conf' , 'r') as usersFile:
	users = usersFile.read().split()

for i in range(0 , len(users)):
	if (users[i][ : 5] == 'puser'):
		users[i] = users[i][1 : ]
		pUsers.append(users[i])

# Add/Remove users to/from WireGuard configuration data:
wgConfigData = {}
wgConfigDataOld = configDataHandler('WireGuard')

wgConfigData['server'] = wgConfigDataOld['server']
wgConfigData['server']['addresses'] = ''

for user in users:
	if (user in wgConfigDataOld):
		wgConfigData[user] = wgConfigDataOld[user]

		serverIPAddress = ''
		tempAllowedIPsList = wgConfigData[user][0]['allowedIPs'].split()
		for item in tempAllowedIPsList:
			if ('/32' in item):
				serverIPAddress = str((IPv4Address(item[:(len(item) - 3)]) - 1))

		wgConfigData['server']['addresses'] += ('Address = ' + serverIPAddress + '/29\n')
	else:
		wgConfigData[user] = []

		serverIPAddress , userIPsList = wgAvailIP(wgConfigData)
		wgConfigData['server']['addresses'] += ('Address = ' + serverIPAddress + '\n')

		for userNum in range(0 , 5):
			privKey , pubKey = wgGenKeys()
			psk = wgGenKeys(genPSK = True)

			wgConfigData[user].append({'header' : ['[Peer]\n' , '[Interface]\n'] , 'comment' : '# ' + user + ' #' + str(userNum + 1) + '\n' , 'privateKey' : ('PrivateKey = ' + privKey + '\n') , 'publicKey' : ('PublicKey = ' + pubKey + '\n') , 'psk' : ('PresharedKey = ' + psk + '\n') , 'allowedIPs' : ('AllowedIPs = ' + userIPsList[userNum][:len(userIPsList[userNum]) - 3] + '/32\n') , 'addresses' : ('Address = ' + userIPsList[userNum][:len(userIPsList[userNum]) - 3] + '/29\n') , 'dns' : ('DNS = 172.31.253.253\n')})

configDataHandler('WireGuard' , wgConfigData)

wgRefresh()

wgGenClientConfigs()


# Add/Remove users to/from Shadowsocks configuration data:
ssConfigData = {}
ssConfigDataOld = configDataHandler('Shadowsocks')

for user in users:
	if (user in ssConfigDataOld):
		ssConfigData[user] = ssConfigDataOld[user]
	else:
		standardPort , pluginPort = ssAvailPorts(ssConfigData)
		ssConfigData[user] = {'standardPort' : standardPort , 'pluginPort' : pluginPort , 'standardPassword' : ssGenPass() , 'pluginPassword' : ssGenPass()}

configDataHandler('Shadowsocks' , ssConfigData)

ssRefresh()

ssGenClientConfigs()

ufwUpdate()
############## End of Daily Update/Maintenance Tasks ##############
