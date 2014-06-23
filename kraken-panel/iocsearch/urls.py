from django.conf.urls import patterns, include, url

from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'iocsearch.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),

    url(r'^gate.php', 'panel.views.gate', name='gate'),
    url(r'^command_results/', 'panel.views.command_results', name='command_results'),
    url(r'^admin/', include(admin.site.urls)),

)
