using System;
using System.IO;
using Newtonsoft.Json;
using System.Security.Cryptography;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;
using System.Net;
using System.Net.Http;

namespace sample
{
    class Program
    {
        static void Main(string[] args)
        {
            // Read the file to string
            var configFileName = "../config.json";
            var reader = new StreamReader(configFileName);
            var json = reader.ReadToEnd();

            // Use the powerful Newtonsoft.Json library 
            // (https://www.newtonsoft.com/json)
            // to covert the string into a Config object
            var config = JsonConvert.DeserializeObject<Config>(json);

            // We use BouncyCastle (BouncyCastle.NetCore) to handle
            // the decryption
            // (https://www.bouncycastle.org/csharp/index.html)

            // Next, we use BouncyCastle's PemReader to read the 
            // decrypt the private key into a RsaPrivateCrtKeyParameters
            // object
            var appAuth = config.boxAppSettings.appAuth;
            var stringReader = new StringReader(appAuth.privateKey);
            var passwordFinder = new PasswordFinder(appAuth.passphrase);
            var pemReader = new PemReader(stringReader, passwordFinder);
            var keyParams = (RsaPrivateCrtKeyParameters) pemReader.ReadObject();

            // In the end, we will use this key in the next steps
            var key = CreateRSAProvider(ToRSAParameters(keyParams));

            // We create a random identifier that helps protect against
            // replay attacks
            byte[] randomNumber = new byte[64];
            RandomNumberGenerator.Create().GetBytes(randomNumber);
            var jti = Convert.ToBase64String(randomNumber);

            // We give the assertion a lifetime of 45 seconds 
            // before it expires
            DateTime expirationTime = DateTime.UtcNow.AddSeconds(45);

            // Next, we are read to assemble the payload
            var claims = new List<Claim>{
                new Claim("sub", config.enterpriseID),
                new Claim("box_sub_type", "enterprise"),
                new Claim("jti", jti),
            };

            String authenticationUrl = "https://api.box.com/oauth2/token";

            // Rather than constructing the JWT assertion manually, we are 
            // using the System.IdentityModel.Tokens.Jwt library.
            var payload = new JwtPayload(
                config.boxAppSettings.clientID, 
                authenticationUrl, 
                claims, 
                null, 
                expirationTime
            );

            // The API support "RS256", "RS384", and "RS512" encryption
            var credentials = new SigningCredentials(
                new RsaSecurityKey(key), 
                SecurityAlgorithms.RsaSha512
            );
            var header = new JwtHeader(signingCredentials: credentials);

            // Finally, let's create the assertion usign the 
            // header and payload
            var jst = new JwtSecurityToken(header, payload);
            var tokenHandler = new JwtSecurityTokenHandler();
            string assertion = tokenHandler.WriteToken(jst);

            // We start by preparing the params to send to 
            // the authentication endpoint
            var content = new FormUrlEncodedContent(new[]
            {
                // This specifies that we are using a JWT assertion
                // to authenticate
                new KeyValuePair<string, string>(
                    "grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                // Our JWT assertion
                new KeyValuePair<string, string>(
                    "assertion", assertion),
                // The OAuth 2 client ID and secret
                new KeyValuePair<string, string>(
                    "client_id", config.boxAppSettings.clientID),
                new KeyValuePair<string, string>(
                    "client_secret", config.boxAppSettings.clientSecret)
            });

            // Make the POST call to the authentication endpoint
            var client = new HttpClient();
            var response = client.PostAsync(authenticationUrl, content).Result;

            var data = response.Content.ReadAsStringAsync().Result;
            var token = JsonConvert.DeserializeObject<Token>(data);
            var accessToken = token.access_token;

            // Folder 0 is the root folder for this account
            // and should be empty by default
            String url = "https://api.box.com/2.0/folders/0";

            client = new HttpClient();
            client.DefaultRequestHeaders.Add(
                "Authorization", "Bearer " + accessToken
            );

            response = client.GetAsync(url).Result;
            data = response.Content.ReadAsStringAsync().Result;

            Console.WriteLine(data);
        }

        // The RsaPrivateCrtKeyParameters need to be converted to RSAParameters.
        // which requires a few utilities from the BouncyCastle library.
        static public RSA CreateRSAProvider(RSAParameters rp)
        {
            var rsaCsp = RSA.Create();
            rsaCsp.ImportParameters(rp);
            return rsaCsp;
        }

        static public RSAParameters ToRSAParameters(RsaPrivateCrtKeyParameters privKey)
        {
            RSAParameters rp = new RSAParameters();
            rp.Modulus = privKey.Modulus.ToByteArrayUnsigned();
            rp.Exponent = privKey.PublicExponent.ToByteArrayUnsigned();
            rp.P = privKey.P.ToByteArrayUnsigned();
            rp.Q = privKey.Q.ToByteArrayUnsigned();
            rp.D = ConvertRSAParametersField(privKey.Exponent, rp.Modulus.Length);
            rp.DP = ConvertRSAParametersField(privKey.DP, rp.P.Length);
            rp.DQ = ConvertRSAParametersField(privKey.DQ, rp.Q.Length);
            rp.InverseQ = ConvertRSAParametersField(privKey.QInv, rp.Q.Length);
            return rp;
        }

        static public byte[] ConvertRSAParametersField(BigInteger n, int size)
        {
            byte[] bs = n.ToByteArrayUnsigned();
            if (bs.Length == size)
                return bs;
            if (bs.Length > size)
                throw new ArgumentException("Specified size too small", "size");
            byte[] padded = new byte[size];
            Array.Copy(bs, 0, padded, size - bs.Length, bs.Length);
            return padded;
        }
    }

    // Define a class that we can parse 
    // the json into
    class Config 
    {
        public class BoxAppSettings {
            public class AppAuth {
                public string privateKey { get; set; }
                public string passphrase { get; set; }
                public string publicKeyID { get; set; }
            }
            public string clientID { get; set; }
            public string clientSecret { get; set; }
            public AppAuth appAuth { get; set; }

        }
        public string enterpriseID { get; set; }
        public BoxAppSettings boxAppSettings { get; set; }
    }

    // First thing, let's define our own implementation of
    // BouncyCastle's IPasswordFinder that takes a password 
    // and converts it to a char[]
    class PasswordFinder : IPasswordFinder
    {
        private string password;
        public PasswordFinder(string _password) { password = _password; }
        public char[] GetPassword() { return password.ToCharArray(); }
    }

    // Parse the JSON using Newtonsoft.JSON to a Token object
    class Token 
    {
        public string access_token { get; set; }
    }
}
