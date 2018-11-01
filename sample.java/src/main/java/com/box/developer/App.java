package com.box.developer;

import java.io.FileReader;
import java.io.StringReader;
import java.security.PrivateKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;

public class App {

    public static void main(String[] args) {
        try {
            // Create a file reader
            FileReader reader = new FileReader("../config.json");

            // Use the powerful GSON library (github.com/google/gson)
            // to covert the string into a Config object
            Gson gson = new GsonBuilder().create();
            Config config = (Config) gson.fromJson(reader, Config.class);

            // We use BouncyCastle to handle the decryption
            // (https://www.bouncycastle.org/java.html)
            Security.addProvider(new BouncyCastleProvider());

            // Using BouncyCastle's PEMParser we convert the
            // encrypted private key into a keypair object
            PEMParser pemParser = new PEMParser(new StringReader(config.boxAppSettings.appAuth.privateKey));
            Object keyPair = pemParser.readObject();
            pemParser.close();

            // Finally, we decrypt the key using the passphrase
            char[] passphrase = config.boxAppSettings.appAuth.passphrase.toCharArray();
            JceOpenSSLPKCS8DecryptorProviderBuilder decryptBuilder = new JceOpenSSLPKCS8DecryptorProviderBuilder()
                    .setProvider("BC");
            InputDecryptorProvider decryptProvider = decryptBuilder.build(passphrase);
            PrivateKeyInfo keyInfo = ((PKCS8EncryptedPrivateKeyInfo) keyPair).decryptPrivateKeyInfo(decryptProvider);

            // In the end, we will use this key in the next steps
            PrivateKey key = (new JcaPEMKeyConverter()).getPrivateKey(keyInfo);

            // We will need the authenticationUrl again later,
            // so it is handy to define here
            String authenticationUrl = "https://api.box.com/oauth2/token";

            // Rather than constructing the JWT assertion manually, we are
            // using the org.jose4j.jwt library.
            JwtClaims claims = new JwtClaims();
            claims.setIssuer(config.boxAppSettings.clientID);
            claims.setAudience(authenticationUrl);
            claims.setSubject(config.enterpriseID);
            claims.setClaim("box_sub_type", "enterprise");
            // This is an identifier that helps protect against
            // replay attacks
            claims.setGeneratedJwtId(64);
            // We give the assertion a lifetime of 45 seconds
            // before it expires
            claims.setExpirationTimeMinutesInTheFuture(0.75f);

            // With the claims in place, it's time to sign the assertion
            JsonWebSignature jws = new JsonWebSignature();
            jws.setPayload(claims.toJson());
            jws.setKey(key);
            // The API support "RS256", "RS384", and "RS512" encryption
            jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA512);
            jws.setHeader("typ", "JWT");
            jws.setHeader("kid", config.boxAppSettings.appAuth.publicKeyID);
            String assertion = jws.getCompactSerialization();

            // We are using the excellent org.apache.http package
            // to simplify the API call

            // Create the params for the request
            List<NameValuePair> params = new ArrayList<NameValuePair>();
            // This specifies that we are using a JWT assertion
            // to authenticate
            params.add(new BasicNameValuePair("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"));
            // Our JWT assertion
            params.add(new BasicNameValuePair("assertion", assertion));
            // The OAuth 2 client ID and secret
            params.add(new BasicNameValuePair("client_id", config.boxAppSettings.clientID));
            params.add(new BasicNameValuePair("client_secret", config.boxAppSettings.clientSecret));

            // Make the POST call to the authentication endpoint
            CloseableHttpClient httpClient = HttpClientBuilder.create().disableCookieManagement().build();
            HttpPost request = new HttpPost(authenticationUrl);
            request.setEntity(new UrlEncodedFormEntity(params));
            CloseableHttpResponse httpResponse = httpClient.execute(request);
            HttpEntity entity = httpResponse.getEntity();
            String response = EntityUtils.toString(entity);
            httpClient.close();

            Token token = (Token) gson.fromJson(response, Token.class);
            String accessToken = token.access_token;

            // Folder 0 is the root folder for this account
            // and should be empty by default
            String url = "https://api.box.com/2.0/folders/0";

            CloseableHttpClient httpClient2 = HttpClientBuilder.create().disableCookieManagement().build();
            HttpGet getRequest = new HttpGet(url);
            getRequest.setHeader(HttpHeaders.AUTHORIZATION, String.format("Bearer %s", accessToken));

            httpResponse = httpClient2.execute(getRequest);
            entity = httpResponse.getEntity();
            String data = EntityUtils.toString(entity);

            System.out.println(data);
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
    }
}

// Define a class that we can parse
// the json into
class Config {
    class BoxAppSettings {
        class AppAuth {
            String privateKey;
            String passphrase;
            String publicKeyID;
        }

        String clientID;
        String clientSecret;
        AppAuth appAuth;
    }

    BoxAppSettings boxAppSettings;
    String enterpriseID;
}

// Parse the JSON using Gson to a Token object
class Token {
    String access_token;
}