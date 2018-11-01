# Samples for "Authenticate with JWT (API)" guide

These are the samples that form the end result of this guide: [Authenticate with JWT (API)](https://developer.box.com/v2.0/docs/construct-jwt-claim-manually).

For more information on the steps in these samples, see the guide.

## Running the samples

First, ensure you have put your `config.json` at the root of this project. See the guide for more details.

```bash
# node
npm install jsonwebtoken axios
node sample.js

# python
pip install pyjwt cryptography
python sample.2.py # python 2
python sample.3.py # python 3

# java
cd sample.java
mvn install
mvn package
mvn dependency:copy-dependencies
java -cp "target/dependency/*:target/sample-1.0-SNAPSHOT.jar" com.box.developer.App

# c#
cd sample.dotnet
dotnet install
dotnet run

# ruby
gem install jwt
ruby sample.rb
```