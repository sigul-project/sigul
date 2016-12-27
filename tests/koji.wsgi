import imp
import sys

# reload(sys)  # Massive hack, due to encoding issues
# sys.setdefaultencoding('UTF8')

sys.path.insert(0, '/usr/share/koji-hub')

_application = imp.load_source('koji_hub', '/usr/share/koji-hub/kojixmlrpc.py').application

def application(environ, start_response):
    environ['koji.hub.ConfigFile'] = '@TESTDIR@/koji/hub.conf'
    environ['koji.hub.ConfigDir'] = ''
    environ['REMOTE_ADDR'] = '-'
    return _application(environ, start_response)
