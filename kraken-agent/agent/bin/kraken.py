import os, time, datetime, re, socket, sys
import subprocess, multiprocessing, threading
import json, requests
from bson import json_util
import configparser, io, platform
import ctypes
import hashlib
import codecs
import random

from _winreg import *
import win32service
import win32serviceutil
import win32event
import servicemanager
import traceback


cc = "ioc.socgen"
cc_port = 8080

class Kraken(multiprocessing.Process, win32serviceutil.ServiceFramework):
    """Main process for IOCFinder"""

    _svc_name_ = "Kraken"
    _svc_display_name_ = "Kraken"


    #### Windows Service functions
    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.running = False
        
    def SvcDoRun(self):
        self.run()
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)
        self.ReportServiceStatus(win32service.SERVICE_STOPPED)

    # auxiliary functions

    def log(self, line, end=""):
        print line
        with codecs.open(self.log_path, mode='a+', encoding='utf-8') as logfile:
            logfile.write(u"[{}] {}\n".format(datetime.datetime.now(), line))
            logfile.flush()

    def readregconfig(self):
        aReg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
        key = OpenKey(aReg, "SOFTWARE\\Kraken")
        val = QueryValueEx(key, 'WorkingDir')[0]
        self.maindir = val
        self.log_path = os.path.join(self.maindir, 'conf', 'log.txt')
        

    # Core Kraken init

    def __init__(self, *args, **kwargs):
        self.readregconfig()
        self.log("Got working dir: %s" % self.maindir)
        

        # Init windows services
        if not kwargs.get('standalone', False):
            self.log("Kraken launched in service mode")
            self.isAlive = True
            win32serviceutil.ServiceFramework.__init__(self, *args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            
        multiprocessing.Process.__init__(self)       
        
        self.hashdeep_output = os.path.join(self.maindir, 'results', 'hashdeep_output.txt')
        self.hashdeep_log = os.path.join(self.maindir, 'results', 'hashdeep_log.txt')

        self.info = self.gather_system_info()
        
        # make hash list
        self.hashes = []
        self.regexs = []
        self.ctph = []
        self.commands = []

        # bootstrap config, can be updated later
        self.config = {
            'cc' : cc,
            'cc_port' : cc_port,
        }

        self.check_files()
        self.log("=== Kraken v1.0 ===")
        self.load_config()
        
        self.total_waited = 0
        self.delay_ms = 100
        self.running = True
        self.update_cycle = -1  # start with a fresh update cycle

    def check_files(self):
        essential_dirs = []
        essential_files = []

        essential_dirs.append(os.path.join(self.maindir, 'results'))
        essential_dirs.append(os.path.join(self.maindir, 'bin'))
        essential_dirs.append(os.path.join(self.maindir, 'conf'))
        essential_dirs.append(os.path.join(self.maindir, 'bin', 'openssl'))

        essential_files.append(os.path.join(self.maindir, 'bin', 'openssl', 'openssl.exe'))
        essential_files.append(os.path.join(self.maindir, 'bin', 'openssl', 'public.pem'))

        self.log("Checking for essential directories...")
        for directory in essential_dirs:
            if not os.path.exists(directory):
                self.log("Directory {} not found. Creating...".format(directory))
                os.makedirs(directory)
        
        self.log("Checking for essential files...")
        for file in essential_files:
            if not os.path.exists(file):
                self.log("FATAL ERROR: %s does not exist" % file)
                sys.exit(-1)

        self.dumpit_exe = os.path.dirname(os.path.join(self.maindir, 'bin', 'openssl', 'DumpIt.exe'))
        self.openssl_exe = os.path.dirname(os.path.join(self.maindir, 'bin', 'openssl', 'openssl.exe'))
        self.public_key = os.path.dirname(os.path.join(self.maindir, 'bin', 'openssl', 'public.pem'))
        self.conf_path = os.path.join(self.maindir, 'conf', 'conf.txt')


    def load_config(self):
        config = configparser.ConfigParser()
        config.read(self.conf_path)
        if not config.has_section('config_update'): return
        for key in config['config_update']:
            self.config[key] = config['config_update'][key]
        self.log("Configuration loaded from %s" % self.conf_path)

    def wait_for_config(self):
        self.log("Waiting for config again")
        while self.running:
            t = datetime.datetime.now()
            if t.hour % 6 == 0 and t.hour != self.update_cycle:
                self.update_cycle = t.hour
                # wait for a specific time
                last_octet = int(self.info['ip'].split(".")[-1])
                timeout = last_octet*(6*60*60/256)
                self.log("Time to fetch config. Waiting an extra {}".format(timeout)) 
                time.sleep(timeout) # sleep an amount of time proportional to the last octet of IP address
                evenout = random.randint(0, 84)
                self.log("Evening out, waiting for {}".format(evenout))
                time.sleep(evenout) # sleep for a random amount of time to further even requests out
                return
            else:
                time.sleep(5)

    def update_config(self, config):
        # we got new config parameters from the server, update them and overwrite local config
        conf_dict = {}
        for c in config:
            conf_dict[c[0]] = c[1]

        self.config['cc'] = conf_dict.get('cc', self.config['cc'])
        self.config['cc_port'] = conf_dict.get('cc_port', self.config['cc_port'])

        self.log("Configuration updated")
        saved_config = configparser.ConfigParser()
        saved_config['config_update'] = self.config
        with open(self.conf_path, 'w+') as configfile:
            saved_config.write(configfile)
        self.log("Configuration file saved to %s" % self.conf_path)


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
        self.log("Starting run loop")
        while self.running:
            self.wait_for_config()
            self.log("Done waiting!")
            try:
                config = self.fetch_config()
                if not config:
                    continue
                self.parse_config(config)

                game = self.hunt()
                self.log("%s matches found" % len(game))
                self.send_hunt_results(game, len(game))

                commands = self.run_commands()
                for result in commands:
                    self.send_command_results(result)

                # Wait for one hour
                # time.sleep(3600)

            except KeyboardInterrupt as e:
                self.running = False
                return
        self.log("Ending run loop")


    def do_http_request(self, uri, params=None, method='GET'):
        url = "http://%s:%s/%s" % (self.config['cc'], self.config['cc_port'], uri)
        data = None

        try:
            if method =='GET':
                r = requests.get(url, params=params)
            if method == 'POST':
                r = requests.post(url, data=params)
            if method == 'json':
                print json_util.dumps(params)
                r = requests.post(url, data=json_util.dumps(params))

            self.log("Sent %s request to %s" % (method, r.url))
            open(os.path.join(self.maindir, 'log.html'), 'w').write(r.content)
            if r.status_code == 500:
                open(os.path.join(self.maindir, 'log-error.html'), 'w').write(r.content)
            r.raise_for_status() # this will raise an exception if code is 4xx/5xx
            self.log("SUCCESS: %s" % r.status_code)
            data = r.content
        except requests.exceptions.ConnectionError, e:
            self.log("ERROR: Could not retreive data: %s" % e)
        except requests.exceptions.HTTPError, e:
            self.log("ERROR: Could not retrieve data: %s" % e)

        return data

    def send_command_results(self, results):
        self.log("Sending command results...", end='')
        self.do_http_request(uri="command_results/", params=results, method='json')

    def send_hunt_results(self, game, matches):
        self.log("Uploading hunt results... ", end='')
        params = {'game':game, 'matches': matches, 'node_id': self.info['node']}
        result = self.do_http_request(uri='gate.php', params=params, method='json')

    def fetch_config(self):
        self.log("Fetching config... ", end='')
        uri = "gate.php"
        config = self.do_http_request(uri=uri, params=self.info)
        if config:
            return config.decode('utf8')

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

        # self.log(self.hashes)
        # self.log(self.regexs)
        # self.log(self.ctph)
        # self.log(self.commands)

    def hunt(self):

        findings = []

        self.log("Checking hashes & regexs...")

        lnum = 0
        
        try:
            f = codecs.open(self.hashdeep_output, 'r', encoding='utf-16')
        except Exception as e:
            self.log("Something went wrong when trying to open %s: %s" % (self.hashdeep_output, e))
            f = []

        for line in f:

            lnum += 1
            for hash in self.hashes:
                if line.find(hash[1]) != -1:

                    self.log("Found %s hash on system: %s (%s)" %(hash[1], line, str(lnum)))
                    findings.append((hash[0], line, lnum))

            for regex in self.regexs:
                if re.search(regex[1], line) != None:
                    self.log("Found %s regex on filesystem: %s (%s)" % (regex[1], line, str(lnum)))
                    findings.append((regex[0], line, lnum))

        self.log("Checking CTPH...")
        lnum = 0
        try:
            f = open(self.hashdeep_output, encoding='mbcs')
        except Exception as e:
            f = []

        for line in f:
            lnum += 1
            for c in self.ctph:
                if line.find(c[1]) != -1:
                    self.log("Found %s CTPH on system: %s (%s)" %(c[1], line, str(lnum)))
                    findings.append((c[0], line, lnum))

        return findings


    def run_commands(self):
        results = []
        for c in self.commands:
            id = c[0]
            cmd_type = c[1].split(';')[0]
            body = c[1].split(';')[1]

            self.log("Execute %s on %s (id:%s)" % (cmd_type, body, id))

            try:
                if cmd_type == 'getfile':
                    data = self.getfile(body, encrypted=False)
                if cmd_type == 'getfileenc':
                    data = self.getfile(body, encrypted=True)
                if cmd_type == 'regget':
                    data = self.regkey(body)
                if cmd_type == 'regfind':
                    data = self.regfind(body)
                done = True
            except Exception as e:
                self.log("run_commands ERROR: %s" % e)
                data = "ERROR: %s" % e
                done = False

            results.append({'data':data, 'command_id': id, 'done': done})

        return results

    def regkey(self, key):
        try:
            args = ['reg', 'query', key]
            retval = subprocess.check_output(args, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        except Exception as e:
            self.log("regkey ERROR: %s" % e)
            retval = "ERROR: %s" % e

        return retval


    def regfind(self, query):
        try:
            key, value = query.split('|')
            args = ['reg', 'query', key, '/f', value, '/s']
            retval = subprocess.check_output(args, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        except Exception as e:
            self.log("regfind ERROR: %s" % e)
            retval = "ERROR: %s" % e

        return retval


    def getfile(self, filename, encrypted=False):
        if not encrypted:
            try:
                retval = open(filename, 'rb').read()
            except Exception as e:
                self.log("getfile ERROR: %s" % e)
                retval = "ERROR: %s" % e
        else:
            try:
                args = [self.openssl_exe, 'smime', '-encrypt', '-aes256', '-in', filename, '-binary', self.public_key]
                data = subprocess.check_output(args, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
                retval = data
            except Exception as e:
                self.log("getfile ERROR: %s" % e)
                retval = "ERROR: %s" % e

        return retval.encode('base64')


    def refresh_hash_lists(self, loop=True):
        self.log("Refreshing hash lists...")
        try:
            self.log("Haslists outdated. Running...")
            output = codecs.open(self.hashdeep_output, 'wb+', encoding='utf-16')
            t_hashdeep = self.hash_directory(directory="C:\\", output_file=output)
            t_hashdeep = self.hash_directory(directory="D:\\", output_file=output)
            
            output.close()

        except KeyboardInterrupt as e:
            self.log("Process stopped... bailing")
            self.run = False
                
    def calculate_hashes(self, filename, chunk_size=102400):
        
        md5 =  hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        if os.stat(filename).st_size > 1024*1024*30:
            return "[> 30 MB, hash skipped]"

        try:
            f = open(filename, 'rb')
        except Exception, e:
            return ":::%s" % e
        
        while True:
            time.sleep(self.delay_ms/1000.0)
            self.total_waited += self.delay_ms/1000.0
            chunk = f.read(chunk_size)
            if len(chunk) == 0:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

        return "%s:%s:%s" % (md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest())


    def hash_directory(self, directory='.', output_file=None):
        self.log("Running hash on directory %s (delay: %sms)" % (directory, self.delay_ms))

        output_file.write("Hashing on %s started on %s\n##############\n\n" % (directory, datetime.datetime.now()))
        
        t0 = datetime.datetime.now()
        for root, dirs, files in os.walk(unicode(directory)):
            for f in files:
                file_path = os.path.join(root, f)
                try:
                    output_file.write(u"%s:%s:%s\n" % (os.path.getsize(file_path), self.calculate_hashes(file_path), file_path))
                except Exception, e:
                    self.log("Error while parsing filename: %s\n%s" % (e, repr(file_path)))
                    output_file.write(u":%s:%s" % (e, repr(file_path)))
                
        t1 = datetime.datetime.now()
        
        self.log("Done! hashdeep run on %s took %s" % (directory, str(t1-t0)))
        output_file.write("Done! hashdeep run on %s took %s" % (directory, str(t1-t0)))
        self.log("Total time waiting: %s" % datetime.timedelta(seconds=self.total_waited))
        return t1

if __name__ == '__main__':

    if len(sys.argv) == 1:  # As launched by the Windows service manager
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(Kraken)
        servicemanager.StartServiceCtrlDispatcher()
    
    else:  # Kraken is being launched manually
        if sys.argv[1] in ['runhash', 'standalone']:
            k = Kraken(standalone=True)
            if sys.argv[1] == 'runhash':
                if len(sys.argv) == 3:
                    k.delay_ms = int(sys.argv[2])
                self.refresh_hash_lists()
            if sys.argv[1] == 'standalone':
                k.run()
        else:
            win32serviceutil.HandleCommandLine(Kraken)