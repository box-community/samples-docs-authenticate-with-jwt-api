const fs = require('fs')
const crypto = require('crypto')
const jwt = require('jsonwebtoken')
const axios = require('axios')
const querystring = require('querystring');

const config = JSON.parse(
  fs.readFileSync('config.json')
)

let run = async () => {
    // In node we don't need to manually decrypt the
  // key, as the JWT library can handle this for us
  let key = {
    key: config.boxAppSettings.appAuth.privateKey,
    passphrase: config.boxAppSettings.appAuth.passphrase
  }

  // We will need the authenticationUrl  again later,
  // so it is handy to define here
  const authenticationUrl = 'https://api.box.com/oauth2/token'

  let claims = {
    'iss': config.boxAppSettings.clientID,
    'sub': config.enterpriseID,
    'box_sub_type': 'enterprise',
    'aud': authenticationUrl,
    // This is an identifier that helps protect against
    // replay attacks
    'jti': crypto.randomBytes(64).toString('hex'),
    // We give the assertion a lifetime of 45 seconds 
    // before it expires
    'exp': Math.floor(Date.now() / 1000) + 45
  }

  let keyId = config.boxAppSettings.appAuth.publicKeyID

  // Rather than constructing the JWT assertion manually, we are 
  // using the jsonwebtoken library.
  let assertion = jwt.sign(claims, key, {
    // The API support "RS256", "RS384", and "RS512" encryption
    'algorithm': 'RS512',
    'keyid': keyId,
  })

  // We are using the excellent axios package 
  // to simplify the API call
  let accessToken = await axios.post(
    authenticationUrl, 
    querystring.stringify({
      // This specifies that we are using a JWT assertion
      // to authenticate
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      // Our JWT assertion
      assertion: assertion,
      // The OAuth 2 client ID and secret
      client_id: config.boxAppSettings.clientID,
      client_secret: config.boxAppSettings.clientSecret
    })
  )
  // Extract the access token from the API response
  .then(response => response.data.access_token)

  // Folder 0 is the root folder for this account
  // and should be empty by default
  let data = await axios.get(
    'https://api.box.com/2.0/folders/0', {
    headers: { 'Authorization' : `Bearer ${accessToken}` }
  }).then(response => response.data)

  console.log(data)
}

run()