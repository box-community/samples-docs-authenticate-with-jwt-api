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

# php
composer install
php sample.php
```

## License

This project has been released under the [Apache 2 license](LICENSE).

## Code of Conduct

All projects in this organization are governed by our [Code of Conduct](CODE_OF_CONDUCT.md).

Instances of abusive, harassing, or otherwise unacceptable behavior may be
reported by contacting the project team at [devrel@box.com](mailto:devrel@box.com). All
complaints will be reviewed and investigated and will result in a response that
is deemed necessary and appropriate to the circumstances. The project team is
obligated to maintain confidentiality with regard to the reporter of an incident.
Further details of specific enforcement policies may be posted separately.

Project maintainers who do not follow or enforce the Code of Conduct in good
faith may face temporary or permanent repercussions as determined by other
members of the project's leadership.