#!/usr/bin/python -u
#
# Copyright 2014 - Puzzle <puzzle1536@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import requests
import json
import libxml2
import subprocess
import sys
import os

from urlparse import parse_qsl, urlparse
from urllib import urlencode
from optparse import OptionParser, OptionGroup
from requests.auth import HTTPBasicAuth
from getpass import getpass

class HTTPBearerAuth(requests.auth.AuthBase):
    def __init__(self, token):
        self.token = token

    def __call__(self, r):
        auth_string = "Bearer " + self.token
        r.headers['Authorization'] = auth_string
        return r

class hubic:
    def __init__(self):

        if options.verbose:
            print "-- Load environment hubic credentials:"

        # Load existing environment variables
        if options.hubic_client_id:
            self.client_id = options.hubic_client_id
        else:
            self.client_id     = os.environ.get('HUBIC_CLIENT_ID', 'None')
        if options.verbose and self.client_id != 'None':
            print "HUBIC_CLIENT_ID=%s"      % self.client_id      

        if options.hubic_client_secret:
            self.client_secret = options.hubic_client_secret
        else:
            self.client_secret = os.environ.get('HUBIC_CLIENT_SECRET', 'None')
        if options.verbose and self.client_secret != 'None':
            print "HUBIC_CLIENT_SECRET=%s"  % self.client_secret  

        if options.hubic_redirect_uri:
            self.redirect_uri = options.hubic_redirect_uri
        else:
            self.redirect_uri  = os.environ.get('HUBIC_REDIRECT_URI', 'None')
        if options.verbose and self.redirect_uri != 'None':
            print "HUBIC_REDIRECT_URI=%s"   % self.redirect_uri   

        if options.hubic_username:
            self.username = options.hubic_username
        else:
            self.username = os.environ.get('HUBIC_USERNAME', 'None')
        if options.verbose and self.username != 'None':
            print "HUBIC_USERNAME=%s"       % self.username       

        if options.hubic_password:
            self.password = options.hubic_password
        else:
            self.password = os.environ.get('HUBIC_PASSWORD', 'None')
        if options.verbose and self.password != 'None':
            print "HUBIC_PASSWORD=%s"       % self.password       


        if options.hubic_refresh_token:
            self.refresh_token = options.hubic_refresh_token
        else:
            self.refresh_token = os.environ.get('HUBIC_REFRESH_TOKEN', 'None')
        if options.verbose and self.refresh_token != 'None':
            print "HUBIC_REFRESH_TOKEN=%s"  % self.refresh_token  

        if options.hubic_access_token:
            self.access_token = options.hubic_access_token
        else:
            self.access_token  = os.environ.get('HUBIC_ACCESS_TOKEN', 'None')
        if options.verbose and self.access_token != 'None':
            print "HUBIC_ACCESS_TOKEN=%s"   % self.access_token   

        if options.os_storage_url:
            self.os_storage_url = options.os_storage_url
        else:
            self.os_storage_url = os.environ.get('OS_STORAGE_URL', 'None')
        if options.verbose and self.os_storage_url != 'None':
            print "OS_STORAGE_URL=%s"       % self.os_storage_url 

        if options.os_auth_token:
            self.os_auth_token = options.os_auth_token
        else:
            self.os_auth_token  = os.environ.get('OS_AUTH_TOKEN', 'None')
        if options.verbose and self.os_auth_token != 'None':
            print "OS_AUTH_TOKEN=%s"       % self.os_auth_token  

        self.token_url = 'https://api.hubic.com/oauth/token'
        self.auth_url  = 'https://api.hubic.com/oauth/auth'
        self.oauth_code = 'None'
        self.token_expire = 'None'

    def auth(self):

        # Do we have access token or an oauthid yet ?
        if self.access_token == 'None' and self.oauth_code == 'None':

            # Request client app creds
            if self.client_id == 'None':
                self.client_id = raw_input('HUBIC_CLIENT_ID=')
            if self.redirect_uri == 'None':
                self.redirect_uri = raw_input('HUBIC_REDIRECT_URI=')

            # Request Hubic account creds
            if self.username == 'None':
                self.username = raw_input('Username: ')
            if self.password == 'None':
                self.password = getpass()

            # Authorization request
            payload = {'client_id' : self.client_id,
                       'redirect_uri' : self.redirect_uri,
                       'scope' : 'usage.r,account.r,getAllLinks.r,credentials.r,activate.w,links.drw',
                       'response_type' : 'code',
                       'state' : 'none'}

            if options.verbose:
                print "-- Request hubic oauth ID:"

            r = requests.get(self.auth_url, params=payload, allow_redirects=False)

            if r.status_code != 200:
                print "Failed to request authorization code, please verify client_id or redirect_uri"
                sys.exit(1)

            try:
                oauthid = libxml2.parseDoc(r.text).xpathEval('/page/opt/OAuthId')[0].content
            except:
                print "Failed to request authorization code, please verify client_id or redirect_uri"
                sys.exit(1)
 

            # Get request code
            payload = {'oauth' : oauthid,
                       'usage': 'r',
                       'account': 'r',
                       'getAllLinks': 'r',
                       'credentials': 'r',
                       'activate': 'w',
                       'links': 'r',
                       'action': 'accepted',
                       'login': self.username,
                       'user_pwd': self.password}

            # Add missing links d & w rights
            data = "%s&links=w&links=d" % urlencode(payload)

            headers = {'content-type': 'application/x-www-form-urlencoded'}

            if options.verbose:
                print "-- Request authorization code:"

            r = requests.post(self.auth_url, data=data, headers=headers, allow_redirects=False)

            try:
                location = urlparse(r.headers['location'])
                self.oauth_code = dict(parse_qsl(location.query))['code']
            except:
                print "Failed to request authorization code, please verify hubic username and password"
                sys.exit(2)

            return self.oauth_code

    def token(self):

        if self.access_token == 'None':

            if self.oauth_code == 'None':
                print "Cannot request token without oauth code"
                return

            if self.client_id == 'None' or self.client_secret == 'None':
                if self.client_id == 'None':
                    self.client_id = raw_input('HUBIC_CLIENT_ID=')
                if self.client_secret == 'None':
                    self.client_secret = raw_input('HUBIC_CLIENT_SECRET=')
                if self.redirect_uri == 'None':
                    self.redirect_uri = raw_input('HUBIC_REDIRECT_URI=')


            payload = {'code' : self.oauth_code,
                       'redirect_uri': self.redirect_uri,
                       'grant_type' : 'authorization_code'}
 
            if options.verbose:
                print "-- Request access token:"

            r = requests.post(self.token_url, payload,
                              auth=HTTPBasicAuth(self.client_id,self.client_secret),
                              allow_redirects=False)
 
            if r.status_code != 200:
                print "%s : %s" % (r.json()['error'], r.json()['error_description'])
                sys.exit(3)

            try:
                self.refresh_token = r.json()['refresh_token']
                self.access_token  = r.json()['access_token']
                self.token_expire  = r.json()['expires_in']
                self.token_type    = r.json()['token_type']

            except:
                print "Something wrong has happened when requesting access token"
                sys.exit(10)
 
            print "HUBIC_ACCESS_TOKEN=%s" % self.access_token
            print "HUBIC_REFRESH_TOKEN=%s" % self.refresh_token
        return self.access_token

    def refresh(self):

        self.token_url = 'https://api.hubic.com/oauth/token'

        if self.refresh_token == 'None':
            print "Cannot request new acces token without refresh token"
            return

        if self.client_id == 'None' or self.client_secret == 'None':
            if self.client_id == 'None':
                self.client_id = raw_input('HUBIC_CLIENT_ID=')
            if self.client_secret == 'None':
                self.client_secret = raw_input('HUBIC_CLIENT_SECRET=')
            if self.redirect_uri == 'None':
                self.redirect_uri = raw_input('HUBIC_REDIRECT_URI=')

        payload = {'refresh_token' : self.refresh_token,
                   'grant_type' : 'refresh_token'}
 
        if options.verbose:
            print "-- Refresh access token:"

        r = requests.post(self.token_url, payload,
                          auth=HTTPBasicAuth(self.client_id,self.client_secret),
                          allow_redirects=False)
 
        if r.status_code != 200:
            print "%s : %s" % (r.json()['error'], r.json()['error_description'])
            sys.exit(4)

        try:
            self.access_token  = r.json()['access_token']
            self.token_expire  = r.json()['expires_in']
            self.token_type    = r.json()['token_type']

        except:
            print "Something wrong has happened when refreshing access token"
            sys.exit(10)
 
        print "HUBIC_ACCESS_TOKEN=%s" % self.access_token
        print "HUBIC_TOKEN_EXPIRE=%s" % self.token_expire
        return self.access_token

    def get(self, hubic_api):

        hubic_api_url = 'https://api.hubic.com/1.0%s' % hubic_api

        if self.access_token != 'None':

            if options.verbose:
                print "-- GET request to hubic API : %s" % hubic_api

            bearer_auth = HTTPBearerAuth(self.access_token)
            r = requests.get(hubic_api_url, auth=bearer_auth)

            try:
                # Check if token is still valid
                if r.status_code == 401 and r.json()['error'] == 'invalid_token' and r.json()['error_description'] == 'expired':
                    # Try to renew if possible
                    print "Access token has expired, try to renew it"
                    self.refresh()
                    r = requests.get(hubic_api_url, auth=bearer_auth)
                if r.status_code == 404 or r.status_code == 500:
                    print "%s : %s" % (r.json()['code'], r.json()['message'])
                    return
 
                if r.status_code != 200:
                    print "%s : %s" % (r.json()['error'], r.json()['error_description'])
                    return

            except:
                print "Something wrong has happened when accesing hubic API (GET request)"
                sys.exit(10)
 
            print r.text

    def post(self, hubic_api, data):

        hubic_api_url = 'https://api.hubic.com/1.0%s' % hubic_api

        if self.access_token != 'None':

            if options.verbose:
                print "-- POST request to hubic API : %s" % hubic_api
                print data

            headers = {'content-type': 'application/x-www-form-urlencoded'}

            bearer_auth = HTTPBearerAuth(self.access_token)
            r = requests.post(hubic_api_url, data=data, headers=headers, auth=bearer_auth)

            try:
                # Check if token is still valid
                if r.status_code == 401 and r.json()['error'] == 'invalid_token' and r.json()['error_description'] == 'expired':
                    # Try to renew if possible
                    print "Access token has expired, try to renew it"
                    self.refresh()
                    r = requests.post(hubic_api_url, auth=bearer_auth)
 
                if r.status_code == 404 or r.status_code == 500:
                    print "%s : %s" % (r.json()['code'], r.json()['message'])
                    return
 
                if r.status_code != 200:
                    print "%s : %s" % (r.json()['error'], r.json()['error_description'])
                    return

            except:
                print "Something wrong has happened when accesing hubic API (POST request)"
                sys.exit(10)
 
            print r.text

    def delete(self, hubic_api):

        hubic_api_url = 'https://api.hubic.com/1.0%s' % hubic_api

        if self.access_token != 'None':

            if options.verbose:
                print "-- DELETE request to hubic API : %s" % hubic_api

            bearer_auth = HTTPBearerAuth(self.access_token)
            r = requests.delete(hubic_api_url, auth=bearer_auth)

            try:
                # Check if token is still valid
                if r.status_code == 401 and r.json()['error'] == 'invalid_token' and r.json()['error_description'] == 'expired':
                    # Try to renew if possible
                    print "Access token has expired, try to renew it"
                    self.refresh()
                    r = requests.post(hubic_api_url, auth=bearer_auth)
 
                if r.status_code == 404 or r.status_code == 500:
                    print "%s : %s" % (r.json()['code'], r.json()['message'])
                    return
 
                if r.status_code != 200:
                    print "%s : %s" % (r.json()['error'], r.json()['error_description'])
                    return

            except:
                print "Something wrong has happened when accesing hubic API (DELETE request)"
                sys.exit(10)
 
            print r.text

    def swift(self, args):

        self.cred_url = 'https://api.hubic.com/1.0/account/credentials'

        if self.access_token != 'None':

            if self.os_storage_url == 'None' or self.os_auth_token == 'None':

                if options.verbose:
                    print "-- Request OpenStack token and storage url:"

                # We must first retrieve storage url and token
                bearer_auth = HTTPBearerAuth(self.access_token)
                r = requests.get(self.cred_url, auth=bearer_auth)
 
                if r.status_code != 200:
                    print "%s : %s" % (r.json()['error'], r.json()['error_description'])
                    sys.exit(6)
 
                try:
                    self.os_auth_token  = r.json()['token']
                    self.os_storage_url = r.json()['endpoint']
 
                except:
                    print "Something wrong has happened when requesting hubic storage credentials"
                    sys.exit(10)

                print "OS_STORAGE_URL=%s" % self.os_storage_url 
                print "OS_AUTH_TOKEN=%s" % self.os_auth_token  

            if options.verbose:
                print "-- Run swift client:"

            cmd = ['swift', "--os-auth-token", self.os_auth_token, '--os-storage-url', self.os_storage_url]
            cmd.extend(args)
            subprocess.call(cmd)

usage = "usage: %prog [options] -- [swift args]"
parser = OptionParser(usage=usage)

parser.add_option("-v",
                  action="store_true", dest="verbose", default=False,
                  help="Display verbose messages")

parser.add_option("--token",
                  action="store_true", dest="token", default=False,
                  help="Request Hubic token")

parser.add_option("--refresh",
                  action="store_true", dest="refresh", default=False,
                  help="Refresh Hubic token")

parser.add_option("--get",
                  action="store", type="string", dest="get",
                  help="Perform GET request to Hubic API")

parser.add_option("--post",
                  action="store", type="string", dest="post",
                  help="Perform POST request to Hubic API")

parser.add_option("--data",
                  action="store", type="string", dest="data",
                  help="urel encoded date for POST request")

parser.add_option("--delete",
                  action="store", type="string", dest="delete",
                  help="Perform DELETE request to Hubic API")

parser.add_option("--swift",
                  action="store_true", dest="swift", default=False,
                  help="Call swift with all the remaining args following \"--\"")

group = OptionGroup(parser, "Hubic access parameters")

group.add_option("--hubic-username",
                  action="store", type="string", dest="hubic_username",
                  help="Hubic username")

group.add_option("--hubic-password",
                  action="store", type="string", dest="hubic_password",
                  help="Hubic password")

group.add_option("--hubic-client-id",
                  action="store", type="string", dest="hubic_client_id",
                  help="Hubic Client ID")

group.add_option("--hubic-client-secret",
                  action="store", type="string", dest="hubic_client_secret",
                  help="Hubic Client Secret")

group.add_option("--hubic-redirect-uri",
                  action="store", type="string", dest="hubic_redirect_uri",
                  help="Hubic Client Redirect URI")

group.add_option("--hubic-access-token",
                  action="store", type="string", dest="hubic_access_token",
                  help="Hubic Client Redirect URI")

group.add_option("--hubic-refresh-token",
                  action="store", type="string", dest="hubic_refresh_token",
                  help="Hubic Client Redirect URI")

parser.add_option_group(group)

group = OptionGroup(parser, "OpenStack Options")

group.add_option("--os-auth-token",
                  action="store", type="string", dest="os_auth_token",
                  help="Hubic/OpenStack access token")

group.add_option("--os-storage-url",
                  action="store", type="string", dest="os_storage_url",
                  help="Hubic/OpenStack storage URL")

parser.add_option_group(group)

(options, args) = parser.parse_args()

hubic = hubic()

# Handle requests to Hubic API
if options.token:
    hubic.auth()
    hubic.token()

if options.get:
    hubic.auth()
    hubic.token()
    hubic.get(options.get)

if options.post:
    hubic.auth()
    hubic.token()
    hubic.post(options.post, options.data)

if options.delete:
    hubic.auth()
    hubic.token()
    hubic.delete(options.delete)

if options.refresh:
    hubic.refresh()

if options.swift:
    hubic.auth()
    hubic.token()
    hubic.swift(args)

