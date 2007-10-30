import logging

from model import Key
from cherrypy import request, response
from turbogears import controllers, expose, flash
from turbogears import identity, redirect

log = logging.getLogger("signserv.controllers")

class Root(controllers.RootController):

    @expose("json")
    def login(self, forward_url=None, previous_url=None, *args, **kw):
        if not identity.current.anonymous \
           and identity.was_login_attempted() \
           and not identity.get_identity_errors():
            raise redirect(forward_url)
        forward_url=None
        previous_url= request.path
        if identity.was_login_attempted():
            msg=_("The credentials you supplied were not correct or "
                   "did not grant access to this resource.")
        elif identity.get_identity_errors():
            msg=_("You must provide your credentials before accessing "
                   "this resource.")
        else:
            msg=_("Please log in.")
            forward_url= request.headers.get("Referer", "/")
        #response.status=403
        return dict(message=msg, previous_url=previous_url, logging_in=True,
                    original_parameters=request.params,
                    forward_url=forward_url)

    @expose("json")
    def list_keys(self):
        return dict(keys=[(key.key_id, key.email) for key in Key.select()])
