from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse, Http404, QueryDict
from django.views.decorators.csrf import csrf_exempt
from django.core.exceptions import ObjectDoesNotExist

from panel.models import Bot, Artifact, Query, Command, Config #, Hunt

import os, urllib, datetime, multiprocessing, json, re
from bson import json_util
# Create your views here.

FILE_DIRECTORY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "UPLOADS")
RAMDUMPS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "RAMDUMPS")
RAMDUMP_PROCESSES = {}

def receive_ramdump_thread(bot):
	print "Getting ready to receive RAM dump from %s" % bot
	import socket
	socket.setdefaulttimeout(60)

	HOST = ''                 # Symbolic name meaning all available interfaces
	PORT = 443             	 # Arbitrary non-privileged port

	cmd = Command.objects.get(target__computer_name=bot, type='ramdump')
	cmd.data = "Waiting for connection"
	cmd.save()

	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.bind((HOST, PORT))
		s.listen(1)
		conn, addr = s.accept()
	except Exception as e:
		print "ERROR: %s" % e
		return
	except KeyboardInterrupt as e:
		print "KeyboardInterrupt received, breaking"
		conn.close()
		cmd.done = False
		cmd.data = "Dump interrupted"
		cmd.save()
		return

	print 'Received connection from', addr
	cmd = Command.objects.get(target__computer_name=bot, type='ramdump')
	cmd.done = True
	cmd.data = "Dump in progres..."
	cmd.save()

	date = datetime.datetime.now()
	date = "%s_%s%s%s" % (date.date(), date.hour, date.minute, date.second)
	filename = os.path.join(RAMDUMPS, "RAMDUMP-%s-%s.ramdump" % (bot, date))

	ram = open(filename, 'wb+')
	try:

		while True:
			data = conn.recv(1024)
			if not data: break
			ram.write(data)
		ram.close()
		conn.close()
	except Exception as e:
		print "ERROR: %s" % e
		cmd.done = False
		cmd.data = "ERROR: %s" % e
		cmd.save()
		return
	except KeyboardInterrupt as e:
		print "KeyboardInterrupt received, breaking"
		ram.close()
		conn.close()
		cmd.done = False
		cmd.data = "Dump interrupted"
		cmd.save()
		return

	ram.close()
	conn.close()

	# record the success
	cmd.done = True
	cmd.data = "RAM dump located in %s" % filename
	cmd.save()

	RAMDUMP_PROCESSES[bot] = None

	return

def record_hunt_info(bot, game):

	for artifact in game:
		# check if artifact has already been seen
		query_id = artifact[0]
		data = artifact[1]

		try:
			a = Artifact.objects.get(original_query__id=query_id, data=data)
		except ObjectDoesNotExist as e:
			a = Artifact()
			a.original_query = Query.objects.get(id=query_id)
			a.data = artifact[1]
			a.bot = bot

		a.last_spotted = datetime.datetime.now()
		a.save()


def register_bot(info):
	b = Bot()
	b.computer_name = info['node']
	b.system = info['system']
	b.node =info['node']
	b.release = info['release']
	b.version = info['version']
	b.machine = info['machine']
	b.processor = info['processor']
	b.ip = info['ip']
	b.first_checkin = datetime.datetime.now()
	b.last_checkin= datetime.datetime.now()

	b.save()

	return b


def build_configuration(bot):

	config = "# begin configuration file\n\n"
	for t in Query.QUERY_TYPES:
		t = t[0] # get the machine-readable label for this artifact type (e.g. 'fs-regex')
		config += '[%s]\n' % t
		lst = ["%s=%s" % (q.id, q.body)for q in Query.objects.filter(type=t)]
		config += "\n".join(lst) + '\n\n'

	commands = Command.objects.filter(target=bot, done=False)
	if commands.count() > 0:
		config += "# bot specific commands\n\n"
		config += "[commands]\n"
		for c in commands:
			config += '%s=%s;%s\n' % (c.id, c.type, c.body)
			if c.type == 'ramdump':
				if RAMDUMP_PROCESSES.get(bot.computer_name, None) == None: # check if the process for this bot is already running
					RAMDUMP_PROCESSES[bot.computer_name] = multiprocessing.Process(target=receive_ramdump_thread, args=(bot.computer_name, ))
					RAMDUMP_PROCESSES[bot.computer_name].start()

	config_updates = Config.objects.all()
	if config_updates.count() > 0:
		config += "# configuration updates\n"
		config += "[config_update]\n"
		for update in config_updates:
			config += "%s=%s\n" % (update.key, update.value)

	return config


@csrf_exempt
def gate(request):

	if request.method == 'POST':
		data = json_util.loads(request.body)
		node_id = data['node_id']
		bot = get_object_or_404(Bot, computer_name=node_id)

		if int(data['matches']) > 0:
			record_hunt_info(bot, data['game'])

		return HttpResponse("OK")

	else:

		node_id = request.GET.get('node', None)
		if not node_id:
			raise Http404

		try: # query DB for node, if not present then create it
			print "Searching node id %s" % node_id
			bot = Bot.objects.get(computer_name=node_id)
			print "Bot %s found. Sending configuration file..." % node_id
		except ObjectDoesNotExist as e:
			print "Bot %s not found. Registering..." % node_id
			bot = register_bot(request.GET.dict())
			print "Success."

		conf = build_configuration(bot)

		bot.last_checkin = datetime.datetime.now()
		bot.save()

		# respond with proper configuration
		return HttpResponse(conf)

@csrf_exempt
def command_results(request):
	if request.method == 'GET':
		raise Http404

	c = json_util.loads(request.body)
	
	id = c['command_id']
	done = c['done']
	data = c['data']

	cmd = get_object_or_404(Command, id=id)
	cmd.done = c['done']

	if cmd.type == 'getfile' or cmd.type == 'getfileenc' and cmd.done == True:
		print cmd.body
		filename = re.sub(r'[^\w]', '_', cmd.body)
		print filename
		filename = "%s-%s.file" % (cmd.target.computer_name, filename)
		if cmd.type == 'getfileenc': filename += '.encrypted'
		with open(os.path.join(FILE_DIRECTORY, filename), 'wb+') as f:
			f.write(c['data'].decode('base64'))
		print "Data written to {}".format(os.path.join(FILE_DIRECTORY, filename))
		cmd.data = "Saved data to %s" % os.path.join(FILE_DIRECTORY, filename)

	if cmd.type == 'regget' and cmd.done == True:
		cmd.data = data

	if cmd.type == 'regfind' and cmd.done == True:
		cmd.data = data

	cmd.save()

	return HttpResponse("OK")


def download_agent(request):
	data = open('/home/kraken/agent.zip', 'rb').read()
	response = HttpResponse(data)
	response['Content-Disposition'] = 'attachment; filename=ioc.zip'
	return response
