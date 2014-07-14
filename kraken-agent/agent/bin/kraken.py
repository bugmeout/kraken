import os, time, datetime, re, socket
import subprocess, multiprocessing, threading
import http.client, json, urllib.parse, urllib.request, bson
import configparser, io, platform
import ctypes



cc = "ioc.socgen"
#cc = '127.0.0.1'
cc_port = 80
cc_ramdump_port = 443

def log(line, end=""):
	print(line)
	with open('log.txt', 'a+') as logfile:
		logfile.write("[%s]"%datetime.datetime.now()+str(line)+"\n")


class Kraken(multiprocessing.Process):
	"""Main process for IOCFinder"""
	def __init__(self):
		multiprocessing.Process.__init__(self)
		log("Launching main process")

		self.ssdeep_output = os.path.dirname(os.path.abspath(__file__)) + '\\..\\results\\ssdeep_output.txt'
		self.hashdeep_output = os.path.dirname(os.path.abspath(__file__)) + '\\..\\results\\hashdeep_output.txt'

		self.hash_thread = None
		self.hash_refresh_period = 1*60*60 # Every 24 hours = 24*60*60
		self.hash_refresh_delta = datetime.timedelta(seconds=self.hash_refresh_period)

		self.config_thread = None
		self.config_refresh_period = 60*60*6 # Every 6 hours = 6*60*60

		self.info = self.gather_system_info()

		if self.info['machine'].find('64') != -1:
			self.hashdeep_exe = os.path.dirname(os.path.abspath(__file__)) + '\\hashdeep64.exe'
		else:
			self.hashdeep_exe = os.path.dirname(os.path.abspath(__file__)) + '\\hashdeep.exe'

		self.ssdeep_exe = os.path.dirname(os.path.abspath(__file__)) + '\\ssdeep.exe'
		self.dumpit_exe = os.path.dirname(os.path.abspath(__file__)) + '\\DumpIt.exe'
		self.openssl_exe = os.path.dirname(os.path.abspath(__file__)) + '\\openssl\\openssl.exe'
		self.public_key = os.path.dirname(os.path.abspath(__file__)) + '\\openssl\\public.pem'

		self.log_path = os.path.dirname(os.path.abspath(__file__)) + '\\..\\conf\\log.txt'

		# make hash list
		self.hashes = []
		self.regexs = []
		self.ctph = []
		self.commands = []

		# bootstrap, can be updated later
		self.config = {
			'cc' : cc,
			'cc_port' : cc_port,
			'cc_ramdump_port' : cc_ramdump_port
		}

		self.load_config()

	def load_config(self):
		config = configparser.ConfigParser()
		config.read(os.path.dirname(os.path.abspath(__file__)) + '\\..\\conf\\conf.txt')
		if 'config_update' not in config: return
		for key in config['config_update']:
			self.config[key] = config['config_update'][key]
		log("Configuration loaded from %s" % os.path.dirname(os.path.abspath(__file__)) + '\\..\\conf\\conf.txt')


	def update_config(self, config):
		# we got new config parameters from the server, update them and overwrite local config
		conf_dict = {}
		for c in config:
			conf_dict[c[0]] = c[1]

		self.config['cc'] = conf_dict.get('cc', self.config['cc'])
		self.config['cc_port'] = conf_dict.get('cc_port', self.config['cc_port'])
		self.config['cc_ramdump_port'] = conf_dict.get('cc_ramdump_port', self.config['cc_ramdump_port'])

		log("Configuration updated")
		saved_config = configparser.ConfigParser()
		saved_config['config_update'] = self.config
		with open(os.path.dirname(os.path.abspath(__file__)) + '\\..\\conf\\conf.txt', 'w+') as configfile:
			saved_config.write(configfile)
		log("Configuration file saved to %s" % os.path.dirname(os.path.abspath(__file__)) + '\\..\\conf\\conf.txt')


	def gather_system_info(self):

		info = platform.uname()

		info = {
			'system': info[0],
			'node':info[1] ,
			'release': info[2],
			'version': info[3],
			'machine': info[4],
			'processor': info[5],
			'ip': socket.gethostbyname(socket.gethostname())
			}

		return info

	def run(self):
		self.hash_thread = threading.Thread(target=self.refresh_hash_lists)
		self.hash_thread.daemon = True
		# self.hash_thread.start()

		while self.run:
			try:
				config = self.fetch_config()
				if not config:
					time.sleep(self.config_refresh_period)
					continue
				self.parse_config(config)

				game = self.hunt()
				log("%s matches found" % len(game))
				self.send_hunt_results(game, len(game))

				commands = self.run_commands()
				self.send_command_results(commands)

				time.sleep(self.config_refresh_period)

			except KeyboardInterrupt as e:
				self.run = False
				return


	def do_http_request(self, uri, data=None):
		log("Requesting URL: http://%s:%s/%s" % (self.config['cc'], self.config['cc_port'], uri))
		info_param = urllib.parse.urlencode(self.info)
		if data == None:
			request = urllib.request.Request(url="http://%s:%s/%s" %(self.config['cc'], self.config['cc_port'], uri))
		else:
			request = urllib.request.Request(url="http://%s:%s/%s" %(self.config['cc'], self.config['cc_port'], uri), data=data)
		try:
			r = urllib.request.urlopen(request)
			data = r.read()
			log(r.getcode())
		except Exception as e:
			data = None
			log("ERROR: Could not retreive data (HTTP status != 200)")

		return data


	def send_command_results(self, results):
		# results = urllib.parse.urlencode(params)
		log("Sending command results...", end='')
		results = bson.dumps(results)
		self.do_http_request(uri="command_results/", data=results)


	def send_hunt_results(self, game, matches):
		log("Uploading hunt results... ", end='')
		params = bson.dumps({'game':game, 'matches':matches, 'node_id': self.info['node']})
		headers = {'Content-type': "application/json"}
		result = self.do_http_request(uri='gate.php', data=params)



	def fetch_config(self):
		log("Fetching config... ", end='')

		info_param = urllib.parse.urlencode(self.info)
		uri = "gate.php?%s" % info_param
		config = self.do_http_request(uri=uri)
		if config: config = config.decode('utf-8')

		return config


	def parse_config(self, config):
		# load config

		self.hashes = []
		self.regexs = []
		self.ctph = []
		self.commands = []

		parser = configparser.RawConfigParser(allow_no_value=True, delimiters=("=",))
		parser.read_string(config)

		if parser.has_section('hash'):
			self.hashes = parser.items('hash')

		if parser.has_section('fs-regex'):
			self.regexs = parser.items('fs-regex')

		if parser.has_section('ctph'):
			self.ctph = parser.items('ctph')

		if parser.has_section('commands'):
			self.commands = parser.items('commands')

		if parser.has_section('config_update'):
			cc = self.config['cc']
			config = parser.items('config_update')
			if cc != self.config['cc']:
				self.fetch_config()
			self.update_config(config=config)

		# log(self.hashes)
		# log(self.regexs)
		# log(self.ctph)
		# log(self.commands)

	def hunt(self):

		findings = []

		log("Checking hashes & regexs...")
		lnum = 0
		try:
			f = open(self.hashdeep_output, encoding='mbcs')
		except Exception as e:
			f = []

		for line in f:
			lnum += 1
			for hash in self.hashes:
				if line.find(hash[1]) != -1:
					log("Found %s hash on system: %s (%s)" %(hash[1], line, str(lnum)))
					findings.append((hash[0], line, lnum))

			for regex in self.regexs:
				if re.search(regex[1], line) != None:
					log("Found %s regex on filesystem: %s (%s)" % (regex[1], line, str(lnum)))
					findings.append((regex[0], line, lnum))

		log("Checking CTPH...")
		lnum = 0
		try:
			f = open(self.hashdeep_output, encoding='mbcs')
		except Exception as e:
			f = []

		for line in f:
			lnum += 1
			for c in self.ctph:
				if line.find(c[1]) != -1:
					log("Found %s CTPH on system: %s (%s)" %(c[1], line, str(lnum)))
					findings.append((c[0], line, lnum))

		return findings


	def run_commands(self):
		results = []
		for c in self.commands:
			id = c[0]
			cmd_type = c[1].split(';')[0]
			body = c[1].split(';')[1]

			log("Execute %s on %s (id:%s)" % (cmd_type, body, id))

			try:
				if cmd_type == 'getfile':
					data = self.getfile(body, encrypted=False)
				if cmd_type == 'getfileenc':
					data = self.getfile(body, encrypted=True)
				if cmd_type == 'regget':
					data = self.regkey(body)
				if cmd_type == 'ramdump':
					data = self.ramdump(self.info['node'])
				if cmd_type == 'regfind':
					data = self.regfind(body)
				done = True
			except Exception as e:
				log("run_commands ERROR: %s" % e)
				data = "ERROR: %s" % e
				done = False

			results.append({'data':data, 'command_id': id, 'done': done})

		return results


	def ramdump(self, botid):
		try:
			time.sleep(2)
			args = [self.dumpit_exe, '/t', cc, '/p', str(self.config['cc_ramdump_port']), '/a']
			log("Executing RAMDUMP: %s" % " ".join(args))
			retval = subprocess.call(args)
		except Exception as e:
			log("ramdump ERROR: %s" % e)
			retval = "ERROR: %s" % e
		return retval


	def regkey(self, key):
		try:
			args = ['reg', 'query', key]
			retval = subprocess.check_output(args, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
		except Exception as e:
			log("regkey ERROR: %s" % e)
			retval = "ERROR: %s" % e

		return retval


	def regfind(self, query):
		try:
			key, value = query.split('|')
			args = ['reg', 'query', key, '/f', value, '/s']
			retval = subprocess.check_output(args, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
		except Exception as e:
			log("regfind ERROR: %s" % e)
			retval = "ERROR: %s" % e

		return retval


	def getfile(self, filename, encrypted=False):
		if not encrypted:
			try:

				retval = open(filename, 'rb').read()
			except Exception as e:
				log("getfile ERROR: %s" % e)
				retval = "ERROR: %s" % e
		else:
			try:
				args = [self.openssl_exe, 'smime', '-encrypt', '-aes256', '-in', filename, '-binary', self.public_key]
				data = subprocess.check_output(args, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
				retval = data
			except Exception as e:
				log("getfile ERROR: %s" % e)
				retval = "ERROR: %s" % e

		return retval


	def refresh_hash_lists(self):

		while self.run:
			log("Refreshing hash lists...")
			try:
				try:
					last = open(self.log_path, 'r+').read().split('=')[1]
					last = datetime.datetime.strptime(last, "%a %b %d %H:%M:%S %Y")
					delta = datetime.datetime.now() - last
					if delta < self.hash_refresh_delta:
						time.sleep((self.hash_refresh_delta - delta).total_seconds())
				except Exception as e:
					log("Logfile not found. It will be created.\n%s" % e)

				# exechour = int(math.floor(self.info['ip'].split('.')[-1])/255.0*8))+10
				# while exechour != datetime.datetime.now().hour:
				# 	time.sleep(60*30)

				output = open(self.hashdeep_output, 'wb+')
				t_hashdeep = self.run_hashdeep(directory="C:/", recursive=True, output_file=output)
				t_hashdeep = self.run_hashdeep(directory="D:/", recursive=True, output_file=output)
				output.close()
				#t_ssdeep = self.run_ssdeep(recursive=True)
				open(self.log_path, 'w+').write("LAST_HASH_RUN=%s" % datetime.datetime.strftime(datetime.datetime.now(), "%a %b %d %H:%M:%S %Y"))

			except Exception as e:
				log("refresh_hash_lists ERROR: %s" % e)
			except KeyboardInterrupt as e:
				log("Process stopped... bailing")
				self.run = False


	def run_hashdeep(self, directory='C:/', recursive=False, output_file=None):

		if not output_file:
			output = open(self.hashdeep_output, 'wb+')
		else:
			output = output_file

		flags = ''
		if recursive: flags += '-r'
		args = [self.hashdeep_exe, flags, directory]

		log("Calling hashdeep on %s..." % directory)

		t0 = datetime.datetime.now()

		startupinfo = subprocess.STARTUPINFO()
		startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
		startupinfo.wShowWindow = subprocess.SW_HIDE
		proc = subprocess.Popen(args, stdout=output, stderr=output, stdin=subprocess.PIPE, startupinfo=startupinfo)

		proc.wait()
		t1 = datetime.datetime.now()

		if not output_file:
			output.close()


		log("Done! hashdeep run on %s took %s" % (directory, str(t1-t0)))
		return t1


	def run_ssdeep(self, directory='C:\\', recursive=False):
		output = open(self.ssdeep_output, 'wb+')

		rerun = []

		t0 = datetime.datetime.now()

		if recursive:
			log("Calling ssdeep recursively...")
			for root, dirs, files in os.walk(directory):
				args = [self.ssdeep_exe, root+"\\*"]
				result = subprocess.call(args, stdout=output, stderr=output)
				if result != 0:
					log("Debug: called ssdeep on files in %s (%s)" % (root, result))
					rerun.append(root)
		else:
			args = [self.ssdeep_exe, directory+'\\*.*']
			result = subprocess.call(args, stdout=output, stderr=output)

		# check for failed directories and run them again, three times max
		for root in rerun:
			self.run_ssdeep(self, root, recursive=False, stdout=output, stderr=output)

		t1 = datetime.datetime.now()

		output.close()

		log("Done! ssdeep run took %s" % str(t1-t0))

		return t1

def main():
	log("Kraken v0.1 alpha")
	k = Kraken()
	k.run()

if __name__ == '__main__':
	main()
