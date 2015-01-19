from django.db import models

from django.utils import timezone
from datetime import timedelta


# Create your models here.
class Bot(models.Model):
	computer_name = models.CharField(max_length=100)
	system = models.CharField(max_length=100)
	node = models.CharField(max_length=100)
	release = models.CharField(max_length=100)
	version = models.CharField(max_length=100)
	machine = models.CharField(max_length=100)
	processor = models.CharField(max_length=100)
	first_checkin = models.DateTimeField('first check-in')
	last_checkin = models.DateTimeField('last check-in')
	ip = models.CharField(max_length=16)

	def __unicode__(self):
		return u"%s (%s %s)" % (self.computer_name, self.system, self.release)

	def artifact_count(self):
		return self.artifact_set.count()

	def is_alive(self):
		return self.last_checkin > timezone.now() - timedelta(seconds=30)
		return self.last_checkin > timezone.now() - timedelta(hours=6)


class Query(models.Model):
	QUERY_TYPES = (('hash', 'Cryptographic hash'), ('ctph', 'Context-triggered piecewise hash'), ('fs-regex', 'Filesystem regular expression'))
	
	type = models.CharField(max_length=50, choices=QUERY_TYPES)
	body = models.CharField(max_length=200)

	def __unicode__(self):
		return u"{0} ({1})".format(self.body, self.get_type_display())


class Artifact(models.Model):
	data = models.CharField(max_length=200)
	original_query = models.ForeignKey(Query)
	bot = models.ForeignKey(Bot)
	last_spotted = models.DateTimeField('last spotted')

	def __unicode__(self):
		return u"{0}".format(self.data)

	def get_query_body(self):
		return self.original_query.body


class Command(models.Model):
	COMMAND_TYPES = (('regget', 'Retrieve arbitrary registry key'), ('regfind','Locate registry key'), ('ramdump', 'Dump volatile memory'), ('getfile', "Retrieve arbitrary file"), ('getfileenc', "Retrieve arbitrary file (encrypted)"))
	RESULTS = ((0, 'Unknown'), (1, 'Success'), (-1, 'Error'))
	
	type = models.CharField(max_length=50, choices=COMMAND_TYPES)
	target = models.ForeignKey(Bot)
	body = models.CharField(max_length=300)
	done = models.BooleanField(default=False)
	data = models.TextField(default="", null=True, blank=True)

	def __unicode__(self):
		return u"{0} on {1}".format(self.get_type_display(), self.target)


class Config(models.Model):
	key = models.CharField(max_length=50)
	value = models.CharField(max_length=200)