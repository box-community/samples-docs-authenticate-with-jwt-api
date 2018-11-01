import json
import os
import time
import binascii
import json

from urllib2 import urlopen
from urllib2 import Request 
from urllib import urlencode

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key

config = json.load(open('config.json'))

appAuth = config["boxAppSettings"]["appAuth"]
privateKey = appAuth["privateKey"]
passphrase = appAuth["passphrase"]

# To decrypt the private key we use the cryptography library
# (https://cryptography.io/en/latest/)
key = load_pem_private_key(
  data=privateKey.encode('utf8'),
  password=passphrase.encode('utf8'),
  backend=default_backend(),
)

# We will need the authentication_url  again later,
# so it is handy to define here
authentication_url = 'https://api.box.com/oauth2/token'

claims = {
  'iss': config['boxAppSettings']['clientID'],
  'sub': config['enterpriseID'],
  'box_sub_type': 'enterprise',
  'aud': authentication_url,
  # This is an identifier that helps protect against
  # replay attacks
  'jti': binascii.hexlify(os.urandom(64)),
  # We give the assertion a lifetime of 45 seconds 
  # before it expires
  'exp': int(round(time.time(), 0) + 45)
}

keyId = config['boxAppSettings']['appAuth']['publicKeyID']

# Rather than constructing the JWT assertion manually, we are 
# using the pyjwt library.
assertion = jwt.encode(
  claims, 
  key, 
  # The API support "RS256", "RS384", and "RS512" encryption
  algorithm='RS512',
  headers={
    'kid': keyId
  }
)

params = urlencode({
  # This specifies that we are using a JWT assertion
  # to authenticate
  'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
  # Our JWT assertion
  'assertion': assertion,
  # The OAuth 2 client ID and secret
  'client_id': config['boxAppSettings']['clientID'],
  'client_secret': config['boxAppSettings']['clientSecret']
}).encode()

# Make the request, parse the JSON,
# and extract the access token
request = Request(authentication_url, params)
response = urlopen(request).read()
access_token = json.loads(response)['access_token']

# Folder 0 is the root folder for this account
# and should be empty by default
request = Request('https://api.box.com/2.0/folders/0', None, {
  'Authorization': "Bearer %s" % access_token
})
response = urlopen(request).read()

print(response)