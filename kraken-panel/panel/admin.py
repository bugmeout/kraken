from django.contrib import admin
from panel.models import Bot, Artifact, Query, Command, Config
# from panel.models import Hunt



class BotAdmin(admin.ModelAdmin):
	readonly_fields = ('computer_name', 'node', 'ip', 'system', 'release', 'version', 'machine', 'processor', 'first_checkin', 'last_checkin', 'is_alive', 'artifact_count')
	list_display = ('computer_name', 'node', 'ip', 'system', 'release', 'version', 'machine', 'processor', 'first_checkin', 'last_checkin',  'is_alive', 'artifact_count')
	search_fields = ['computer_name', 'ip']
	fieldsets = (
		(None, {
			'fields': (('computer_name', 'ip', 'first_checkin', 'last_checkin'), )
		}),
		("Advanced", {
			'fields': (('system', 'release', 'version', 'machine', 'processor'), )
		}),
		("Artifacts", {
			'fields': ('artifact_count', )
			})
		("Status", {
			'fields': ('is_alive', )
			})
		)

	list_select_related = ('artifact', )

class ArtifactAdmin(admin.ModelAdmin):

	list_display = ('original_query', 'bot', 'last_spotted', 'data', )
	readonly_fields = list_display
	search_fields = ['original_query']
	list_select_related = ('original_query', )

	

# class HuntAdmin(admin.ModelAdmin):
# 	list_display = ('date_found', 'bot')

class QueryAdmin(admin.ModelAdmin):
	list_display = ('type', 'body')
	search_fields = ['body']



class CommandAdmin(admin.ModelAdmin):
	list_display = ('type', 'target', 'body', 'done', 'data')
	search_fields = ['body', 'done', 'target__comuter_name']
	raw_id_fields = ['target']

class ConfigAdmin(admin.ModelAdmin):
	list_display = ('key', 'value')
	search_fields = ['key']



# Register your models here.
admin.site.register(Bot, BotAdmin)
admin.site.register(Artifact, ArtifactAdmin)
# admin.site.register(Hunt, HuntAdmin)
admin.site.register(Query, QueryAdmin)
admin.site.register(Command, CommandAdmin)
admin.site.register(Config, ConfigAdmin)