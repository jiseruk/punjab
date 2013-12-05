"""
 spnego prebinding interface
"""
from twisted.python import components
from twisted.web import server, resource
from twisted.internet import defer, task
from twisted.python import log

from httpb import *

from zope.interface import Interface, implements

try:
    from twisted.words.xish import domish
except ImportError:
    from twisted.xish import domish

import hashlib, time
import error
from session import make_session
import punjab
from punjab.xmpp import ns


NS_BIND = 'http://jabber.org/protocol/httpbind'
NS_FEATURES = 'http://etherx.jabber.org/streams'

class DummyElement:
    """
    dummy element for a quicker parse
    """
    # currently not used
    def __init__(self, *args, **kwargs):

        self.children = []



class SpnegoElementStream(domish.ExpatElementStream):
    """
    add rawXml to the elements
    """

    def __init__(self, prefixes=None):
        domish.ExpatElementStream.__init__(self)
        self.prefixes = {}
        if prefixes:
            self.prefixes.update(prefixes)
        self.prefixes.update(domish.G_PREFIXES)
        self.prefixStack = [domish.G_PREFIXES.values()]
        self.prefixCounter = 0


    def getPrefix(self, uri):
        if not self.prefixes.has_key(uri):
            self.prefixes[uri] = "xn%d" % (self.prefixCounter)
            self.prefixCounter = self.prefixCounter + 1
        return self.prefixes[uri]

    def prefixInScope(self, prefix):
        stack = self.prefixStack
        for i in range(-1, (len(self.prefixStack)+1) * -1, -1):
            if prefix in stack[i]:
                return True
        return False

    def _onStartElement(self, name, attrs):
        # Generate a qname tuple from the provided name
        attr_str   = ''
        defaultUri = None
        uri        = None
        qname = name.split(" ")
        if len(qname) == 1:
            qname = ('', name)
            currentUri = None
        else:
            currentUri = qname[0]
        if self.currElem:
            defaultUri = self.currElem.defaultUri
            uri = self.currElem.uri

        if not defaultUri and currentUri in self.defaultNsStack:
            defaultUri = self.defaultNsStack[1]

        if defaultUri and currentUri != defaultUri:

            raw_xml = u"""<%s xmlns='%s'%s""" % (qname[1], qname[0], '%s')

        else:
            raw_xml = u"""<%s%s""" % (qname[1], '%s')


        # Process attributes

        for k, v in attrs.items():
            if k.find(" ") != -1:
                aqname = k.split(" ")
                attrs[(aqname[0], aqname[1])] = v

                attr_prefix = self.getPrefix(aqname[0])
                if not self.prefixInScope(attr_prefix):
                    attr_str = attr_str + " xmlns:%s='%s'" % (attr_prefix,
                                                              aqname[0])
                    self.prefixStack[-1].append(attr_prefix)
                attr_str = attr_str + " %s:%s='%s'" % (attr_prefix,
                                                       aqname[1],
                                                       domish.escapeToXml(v,
                                                                          True))
                del attrs[k]
            else:
                v = domish.escapeToXml(v, True)
                attr_str = attr_str + " " + k + "='" + v + "'"

        raw_xml = raw_xml % (attr_str,)

        # Construct the new element
        e = domish.Element(qname, self.defaultNsStack[-1], attrs, self.localPrefixes)
        self.localPrefixes = {}

        # Document already started
        if self.documentStarted == 1:
            if self.currElem != None:
                if len(self.currElem.children)==0 or isinstance(self.currElem.children[-1], domish.Element):
                    if self.currRawElem[-1] != ">":
                        self.currRawElem = self.currRawElem +">"

                self.currElem.children.append(e)
                e.parent = self.currElem

            self.currRawElem = self.currRawElem + raw_xml
            self.currElem = e
        # New document
        else:
            self.currRawElem = u''
            self.documentStarted = 1
            self.DocumentStartEvent(e)

    def _onEndElement(self, _):
        # Check for null current elem; end of doc
        if self.currElem is None:
            self.DocumentEndEvent()

        # Check for parent that is None; that's
        # the top of the stack
        elif self.currElem.parent is None:
            if len(self.currElem.children)>0:
                self.currRawElem = self.currRawElem + "</"+ self.currElem.name+">"
            else:
                self.currRawElem = self.currRawElem + "/>"
            self.ElementEvent(self.currElem, self.currRawElem)
            self.currElem = None
            self.currRawElem = u''
        # Anything else is just some element in the current
        # packet wrapping up
        else:
            if len(self.currElem.children)==0:
                self.currRawElem = self.currRawElem + "/>"
            else:
                self.currRawElem = self.currRawElem + "</"+ self.currElem.name+">"
            self.currElem = self.currElem.parent

    def _onCdata(self, data):
        if self.currElem != None:
            if len(self.currElem.children)==0:
                self.currRawElem = self.currRawElem + ">" + domish.escapeToXml(data)
                #self.currRawElem = self.currRawElem + ">" + data
            else:
                self.currRawElem = self.currRawElem  + domish.escapeToXml(data)
                #self.currRawElem = self.currRawElem  + data

            self.currElem.addContent(data)

    def _onStartNamespace(self, prefix, uri):
        # If this is the default namespace, put
        # it on the stack
        if prefix is None:
            self.defaultNsStack.append(uri)
        else:
            self.localPrefixes[prefix] = uri

    def _onEndNamespace(self, prefix):
        # Remove last element on the stack
        if prefix is None:
            self.defaultNsStack.pop()

def elementStream():
    """ Preferred method to construct an ElementStream

    Uses Expat-based stream if available, and falls back to Sux if necessary.
    """
    try:
        es = SpnegoElementStream()
        return es
    except ImportError:
        if domish.SuxElementStream is None:
            raise Exception("No parsers available :(")
        es = domish.SuxElementStream()
        return es


class ISpnegoService(IHttpbService):
    """
    Interface for http binding class
    TODO: Added value of a separate interface?
    """
    pass



class ISpnegoFactory(IHttpbFactory):
    """
    Factory class for generating binding sessions.
    TODO: Added value of a separate interface?
    """
    pass



class Spnego(Httpb):
    """
    Httpb extension for prebinding with SPNEGO (Kerberos through Negotiate authentication).
    """
    def __init__(self, service, v = 0):
        """Initialize.
        """
	Httpb.__init__(self, service, v)

    #
    # In response to a GET request, return a page with the protocol description
    #
    def render_GET(self, request):
        """
        GET is not used, print docs.
        """
        request.setHeader('Access-Control-Allow-Origin', '*')
        request.setHeader('Access-Control-Allow-Headers', 'Content-Type')
        return """<html>
                 <body>
                 <a href='http://metajack.im/2009/12/14/fastest-xmpp-sessions-with-http-prebinding/'>Prebinding interface</a> - BOSH
                 </body>
               </html>"""

    #
    # In response to a POST of a <body/>, start prebinding authentication
    #
    def render_POST(self, request):
        """
        Parse received xml
        """
	self.service.v = 1 #TODO:VERBOSE#
        request.setHeader('Access-Control-Allow-Origin', '*')
        request.setHeader('Access-Control-Allow-Headers', 'Content-Type')
        request.content.seek(0, 0)
        if self.service.v:
		log.msg('HEADERS %s:' % (str(time.time()),))
		log.msg(request.received_headers)
		log.msg("SPNEGO POST : ")
		log.msg(str(request.content.read()))
		request.content.seek(0, 0)

        self.hp       = HttpbParse()
        try:
            body, xmpp_elements = self.hp.parse(request.content.read())
            self.hp._reset()

            if getattr(body, 'name', '') != "body":
                if self.service.v:
                    log.msg('Client sent bad POST data')
                self.send_http_error(400, request)
                return server.NOT_DONE_YET
        except domish.ParserError:
            log.msg('ERROR: Xml Parse Error')
            log.err()
            self.hp._reset()
            self.send_http_error(400, request)
            return server.NOT_DONE_YET
        except:
	    log.msg('ERROR: General exception while parsing XML body')
            log.err()
            # reset parser, just in case
            self.hp._reset()
            self.send_http_error(400, request)
            return server.NOT_DONE_YET
        else:
            if self.service.inSession(body):
                # sid is an existing session
                if body.getAttribute('rid'):
                    request.rid = body['rid']
                    if self.service.v:
                        log.msg(request.rid)

	#TODO# Parameterise with configured path variable 'spnego'
	pathcompo = request.path.split ('/')
	if pathcompo [-1:] == ['']:
		pathcompo = pathcompo [:-1]
	if pathcompo [:2] != ['', 'spnego-prebind']:
		log.msg ('This request was not sent to /spnego-prebind')
		self.send_http_error ('404', request, 'not-found')
	if pathcompo [2:] == []:
		#
		# Initial post; find a stream ID and redirect to it
		#
		sid = request.getCookie ('sid')
		if sid:
			log.msg ('Redirecting client to SID ' + sid + ' (from cookie)')
			request.setHeader ('Location: /spnego-prebind/' + sid)	#TODO# Use parameter 'spnego' from configuration
			self.send_http_error ('307', request, 'redirect', typ='modify')
			return 0 #TODO# server.DONE
		else:
			sid = None
	else:
		sid = pathcompo [2]
		log.msg ('Continuing with SID ' + sid + ' (from path extension)')

	if (not sid) or (not self.service.sessions.has_key (sid)):
		log.msg ('Session does not exist (anymore) -- starting a new one')
		session, deferred = self.service.startSession (body, xmpp_elements)
		deferred.addCallback (self.return_sid, session, request)
		deferred.addErrback (self.return_error, request)
		return server.NOT_DONE_YET

	session = self.service.sessions [sid]

	authcode = request.getHeader ('Authorization')
	if not (authcode and authcode.split (' ') [:1] == ['Negotiate']):
		#
		# Start the challenge/response chain
		#
		xmppstring = '<auth xmlns="urn:ietf:params:xml:ns:xmpp-sasl" mechanism="GSSAPI"/>'
	else:
		#
		# Continue the challenge/response chain
		#
		authcode = (authcode + ' ').split (' ', 1) [1]
		authcode = [ c for c in authcode if c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=' ]
		xmppstring = '<response xmlns="urn:ietf:params:xml:ns:xmpp-sasl">' + authcode + '</response>'

	log.msg ('RvR: Preparing to send over XMPP session: ' + xmppstring)
	#TODO# Setup deferred actions
	body ['sid'] = sid
	session, deferred = self.service.parseBody (body, [xmppstring])
	session.rawDataIn ('')
	log.msg ('Pulled XML data (usually features) from stream: ' + str (session.raw_buffer))
	session.rawDataOut (xmppstring)
	log.msg ('RvR: Filing callback and errback')
	deferred.addCallback (self.return_spnego, session, request)
	log.msg ('RvR: Filed callback and will file errback')
	deferred.addErrback (self.return_error, request)
	log.msg ('RvR: Filed callback and errback and now continuing processing')
        return server.NOT_DONE_YET


    #
    # When a new XMPP session has been created, return its SID through redirection
    #
    def return_sid (self, data, session, request):
	log.msg ('Returning session in the SPNEGO variation -- as a redirect')
        if session.xmlstream is None:
            self.send_http_error (200, request, 'remote-connection-failed')
            return server.NOT_DONE_YET

	sid = session.sid
	log.msg ('Started session ' + sid + ' over XMPP, returning it in a redict URL')
	request.setHeader ('Location', '/spnego-prebind/' + session.sid)	#TODO# Use parameter 'spnego' from configuration
	self.send_http_error ('307', request, 'redirect', typ='modify')
	#OR?# return server.NOT_DONE_YET
        request.finish ()

    #
    # Receive an XMPP response, which should be one of <challenge/>, <success/> or <failure/>
    #
    def return_spnego (self, data, session, request):
	log.msg ('Need an SPNEGO response for ' + str (data) + ' :: ' + str (type (data)) + ' of len ' + str (len (data)))
	data = data [0]
	log.msg ('Need an SPNEGO response for ' + str (data) + ' :: ' + str (type (data)))
	if data.name == 'challenge':
	    log.msg ('RvR: Data name is "challenge"')
	    challenge = str (data)
	    log.msg ('Challenge is ' + data)
	    request.setHeader ('WWW-Authenticate', 'Negotiate ' + challenge)
	    self.send_http_error ('401', request, 'not-authorized', typ='modify')
	    return server.NOT_DONE_YET
	elif data.name == 'success':
	    log.msg ('RvR: Data name is "success"')
	    iq = domish.Element ((NS_CLIENT, "iq"), { 'type': result, 'id': 'TODO' })
	    bnd = domish.Element ((NS_BIND, "bind"))
	    jid = domish.Element ((NS_BIND, "jid"))
	    jid.children.append (session.jid)
	    bnd.chilren.append (jid)
	    iq.children.append (bnd)
	    return self.return_httpb (iq, session, request)
	else:
	    log.msg ('RvR: Data name is neither "challenge" nor "success", but "' + str (data.name) + '"')
	    # return self.return_httpb (data, session, request)
	    deferred = defer.Deferred ()
	    log.msg ('RvR: Filing repeated callback and errback')
	    deferred.addCallback (self.return_spnego, session, request)
	    log.msg ('RvR: Filed repeated callback and will file errback')
	    deferred.addErrback (self.return_error, request)
	    log.msg ('RvR: Filed repeated callback and errback and now continuing processing')
	    session.appendWaitingRequest (deferred, session.rid, poll=session.polling)
	    log.msg ('RvR: Appended new deferred structure to session')
	    # return server.NOT_DONE_YET
	    return 0 #TODO# server.DONE



components.registerAdapter(Spnego, ISpnegoService, resource.IResource)


class SpnegoService(HttpbService):

    #TODO# Added value of a separate SPNEGO-service-class?!?

    implements(ISpnegoService)

    white_list = []
    black_list = []

    def __init__(self,
                 verbose = 0, polling = 15,
                 use_raw = False, bindAddress=None,
                 session_creator = None):
	HttpbService.__init__ (self, verbose, polling, use_raw, bindAddress, session_creator)

