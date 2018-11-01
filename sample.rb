require 'json'
require "openssl" 
require 'securerandom'
require 'jwt'
require 'json'
require 'uri'
require 'net/https'

config = JSON.parse(
  File.read('config.json')
)

# Your Ruby will need to have be compiled 
# with OpenSSL for this to work

# In the end, we will use this key in the next steps
appAuth = config['boxAppSettings']['appAuth']
key = OpenSSL::PKey::RSA.new(
  appAuth['privateKey'],
  appAuth['passphrase']
)

# We will need the authentication_url  again later,
# so it is handy to define here
authentication_url = 'https://api.box.com/oauth2/token'

claims = {
  iss: config['boxAppSettings']['clientID'],
  sub: config['enterpriseID'],
  box_sub_type: 'enterprise',
  aud: authentication_url,
  # This is an identifier that helps protect against
  # replay attacks
  jti: SecureRandom.hex(64),
  # We give the assertion a lifetime of 45 seconds 
  # before it expires
  exp: Time.now.to_i + 45
}

keyId = appAuth['publicKeyID']

# Rather than constructing the JWT assertion manually, we are 
# using the pyjwt library.
# The API support "RS256", "RS384", and "RS512" encryption
assertion = JWT.encode(claims, key, 'RS512', { kid: keyId })

# We are using the excellent axios package 
# to simplify the API call
params = URI.encode_www_form({
  # This specifies that we are using a JWT assertion
  # to authenticate
  grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
  # Our JWT assertion
  assertion: assertion,
  # The OAuth 2 client ID and secret
  client_id: config['boxAppSettings']['clientID'],
  client_secret: config['boxAppSettings']['clientSecret']
})

# Make the request
uri = URI.parse(authentication_url)
http = Net::HTTP.start(uri.host, uri.port, use_ssl: true)
request = Net::HTTP::Post.new(uri.request_uri)
request.body = params
response = http.request(request)

# Parse the JSON and extract the access token
access_token = JSON.parse(response.body)['access_token']

# Folder 0 is the root folder for this account
# and should be empty by default
uri = URI.parse('https://api.box.com/2.0/folders/0')
http = Net::HTTP.new(uri.host, uri.port)
http.use_ssl = true

response = http.get(uri.request_uri, {
  'Authorization' => "Bearer #{access_token}"
}).body

puts response