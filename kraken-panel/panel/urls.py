from django.conf.urls import patterns, url
from panel import views

urlpatterns = patterns('',
		url(r'^$', views.gate, name='gate')
	)