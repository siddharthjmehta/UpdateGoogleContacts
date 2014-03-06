from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app, login_required
from google.appengine.api import users
from google.appengine.api import mail
import gdata.gauth
import base64
import gdata.service
import atom.http_core
import traceback
import logging
from google.appengine.ext import db
from google.appengine.api import users
from google.appengine.ext import ereporter
from urlparse import urlparse

ereporter.register_logger()

import gdata.contacts.client
# https://developers.google.com/google-apps/contacts/v3/#contact_entry

from config import *


class Home(webapp.RequestHandler):

    def get(self):
        """Home"""
        if users.get_current_user():
            self.redirect("/step1")
        else:
            self.response.out.write("<a href='/step1'>Sign in google</a><br />")


class Fetcher(webapp.RequestHandler):

    @login_required
    def get(self):
        """This handler is responsible for fetching an initial OAuth
        request token and redirecting the user to the approval page."""

        current_user = users.get_current_user()
        # verify if token exist
        # try:
        #    access_token = gdata.gauth.ae_load('access_token_%s' % current_user.user_id())
        #except:
        #    pass

        #create token
        token = gdata.gauth.OAuth2Token(client_id = SETTINGS['CLIENT_ID'],
                                        client_secret = SETTINGS['CLIENT_SECRET'],
                                        scope = ' '.join(SETTINGS['SCOPES']),
                                        user_agent = SETTINGS['USER_AGENT'])

        url = token.generate_authorize_url(redirect_uri = SETTINGS['OAUTH2CALLBACK'])

        #save token to datastore
        gdata.gauth.ae_save(token, current_user.user_id())

        #message = """<a href="%s">
        #Request token for the Google Documents Scope</a>"""

        #self.response.out.write(message % url)
        #self.response.out.write(" ; redirect uri : %s" % token.redirect_uri)
        self.redirect(url)


class RequestTokenCallback(webapp.RequestHandler):
    """

    """

    @login_required
    def get(self):
        """When the user grants access, they are redirected back to this
        handler where their authorized request token is exchanged for a
        long-lived access token."""

        current_user = users.get_current_user()

        #get token from callback uri
        url = atom.http_core.Uri.parse_uri(self.request.uri)

        # get token from datastore
        token = gdata.gauth.ae_load(current_user.user_id())
        token.redirect_uri = SETTINGS['OAUTH2CALLBACK']


        if 'error' in url.query:
            self.response.out.write("Oups..")
        else:
            access_token_key = token.get_access_token(url.query)
            access_token_key = 'access_token_%s' % current_user.user_id()
            gdata.gauth.ae_save(token, access_token_key)
            #self.response.out.write("<a href='/contacts'>Contacts</a><br />")
            self.redirect("/groups")



class Groups(webapp.RequestHandler):


    @login_required
    def get(self):
        """print contacts"""
        current_user = users.get_current_user()
        access_token_key = 'access_token_%s' % current_user.user_id()
        token = gdata.gauth.ae_load(access_token_key)
        gcontacts_client = gdata.contacts.client.ContactsClient(source = SETTINGS['APP_NAME'])
        gcontacts_client = token.authorize(gcontacts_client)

        self.PrintAllGroups(gcontacts_client)

    def PrintAllGroups(self, gd_client):

        query = gdata.contacts.client.ContactsQuery()
        query.max_results = 9999
        feed = gd_client.GetGroups(q = query)
        self.response.out.write("<ul>")
        for entry in feed.entry:
            self.response.out.write("""
            <li><a href=\"/group?id=%s\" title=\"Créé le %s\">%s</a></li>""" %
            (entry.id.text.encode('utf-8'),
             entry.updated.text.encode('utf-8'),
             entry.title.text.encode('utf-8')))

        self.response.out.write("</ul>")

class Group(webapp.RequestHandler):


    @login_required
    def get(self):
        """print contacts"""
        current_user = users.get_current_user()
        access_token_key = 'access_token_%s' % current_user.user_id()
        token = gdata.gauth.ae_load(access_token_key)
        gcontacts_client = gdata.contacts.client.ContactsClient(source = SETTINGS['APP_NAME'])
        gcontacts_client = token.authorize(gcontacts_client)

        self.PrintContacts(gcontacts_client, str(self.request.get("id")))

    def PrintContacts(self, gd_client, group):

        query_contacts = gdata.contacts.client.ContactsQuery()
        feed = gd_client.GetContacts()
        query_contacts.max_results = 9999
        query_contacts.group = group
        feed = gd_client.GetContacts(q = query_contacts)

        feed_groups = gd_client.GetGroup(group)

        self.response.out.write("<h1>%s</h1>" % feed_groups.title.text.encode('utf-8'))

        self.response.out.write("<ul>")
        for entry in feed.entry:
            
            #Check if already exist
            q = db.GqlQuery("select * from MyContact where id = :1", entry.id.text).get()
            
            #for e in q:
            #    debug = db.to_dict(e)
            #    logging.info("DEBUG: ====>" + str(debug))
            #    self.response.out.write("\n" + str(debug))
                
           
               
            if not q:
                try:
                    m = MyContact(users.get_current_user(), entry.id.text, entry.name.full_name.text)
                    m.put()
                except:
                    stacktrace = traceback.format_exc()
                    logging.error("%s", stacktrace)
                    
            m = db.GqlQuery("select * from MyContact where id = :1", entry.id.text).get()
            
            
            #for key in m:
            #    self.response.out.write("\n%s : %s" % (key, m[key]))
                
            #try:
            #    contact_key = db.Key.from_path('MyContact',users.get_current_user(), entry.id.text)
            #    m = MyContact.get(contact_key)
            #except:
            #    stacktrace = traceback.format_exc()
            #    logging.error("%s", stacktrace)  
                    
            
            
                
            if m.key():    
                self.response.out.write("""<li><a href=\"\ModifyMe?hash=%s">%s</a> : """
                                    % (m.key(),
                                       entry.name.full_name))
            
            #for email in entry.email:
            #    if email.primary == 'true':
            #        self.response.out.write(" <b>%s</b>" % email.address.encode('utf-8'))
            #    else:
            #        self.response.out.write(" %s" % email.address.encode('utf-8'))
            #self.response.out.write("</li>")



        self.response.out.write("</ul>")




class ModifyMe(webapp.RequestHandler):

    @login_required
    def get(self):
        """print contacts"""
        current_user = users.get_current_user()
        access_token_key = 'access_token_%s' % current_user.user_id()
        token = gdata.gauth.ae_load(access_token_key)
        gcontacts_client = gdata.contacts.client.ContactsClient(source = SETTINGS['APP_NAME'])
        gcontacts_client = token.authorize(gcontacts_client)

        self.PrintContact(gcontacts_client,str(self.request.get("hash")))

    def PrintContact(self, gd_client, key):

        
        try:
            m = MyContact.get(key)
        except:
            stacktrace = traceback.format_exc()
            logging.error("%s", stacktrace) 
         
        
        ####
        try:
            contact = gd_client.GetContact(str(m.id).replace("http","https"))
            for o in m.owner:
                self.response.out.write("<ul>")
                self.response.out.write("<li>%s</li>" % m.owner)
                self.response.out.write("<li>%s</li>" % m.firstname)
        except:
            stacktrace = traceback.format_exc()
            logging.error("%s", stacktrace)
          
            
        try:    
            if contact.content:
                self.response.out.write("<li>%s</li>", contact.content.text)
        except:
            stacktrace = traceback.format_exc()
            logging.error("%s", stacktrace) 
         
        try:    
            for email in contact.email:
                if email.primary and email.primary == 'true':
                    self.response.out.write("<li>mail : %s</li>" % email.address)
                    
            self.response.out.write("</ul>")
        
        
        except:
            stacktrace = traceback.format_exc()
            logging.error("%s", stacktrace) 
        
        
        






class MyContact(db.Model):
    owner = db.UserProperty(indexed=True)
    firstname = db.StringProperty()
    id = db.StringProperty(indexed=True)

    #def __init__(self, owner, idContact, firstname):
    #    db.Model.__init__(self)
    #    self.owner = owner
    #    self.firstname = firstname
    #    self.id = idContact

    #    return None

    def __hash__(self):
        return base64.encodestring(self.owner.__str__() + self.id)

    def __str__(self):
        return self.owner, " : ", self.id, " ", self.firstname




def main():
    application = webapp.WSGIApplication([('/', Home),
                                          ('/step1', Fetcher),
                                          ('/oauth2callback', RequestTokenCallback),
                                          ('/groups', Groups),
                                          ('/group', Group),
                                          ('/ModifyMe', ModifyMe)],
                                         debug = True)
    run_wsgi_app(application)

if __name__ == '__main__':
    main()
