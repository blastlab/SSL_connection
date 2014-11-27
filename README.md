# Connecting by SSL Sockets using self-signed certificates

This library is developed to make [SSLContext](https://docs.oracle.com/javase/7/docs/api/javax/net/ssl/SSLContext.html) initialization easier. It may be used in Android applications as well. See more about self-signed SSL certificates and possible uses in IoT on [our blog](http://blog.blastlab.co/post/103564752561/security-in-iot).

## Creating certificate for server

Our keystore will keep pair of public and private key. It can be generated with command: It can be generated with this sample command in /src/main/resources of our server application:

```
keytool -genkey -alias serverca -keyalg RSA -keystore keystore.jks -validity 30
```

Validity parameter is number of days the certificate will be valid.

As keystore password in example application there is set "ServerKeystorePass" and as "ServerKeyPass" as key password.

Now export public certificate from keystore using command:

```
keytool -export -alias serverca -file server.cer -keystore keystore.jks
```

By default certificate is generated in binary DER form - see http://en.wikipedia.org/wiki/X.509#Certificate_filename_extensions for more info. You can convert this certificate to Base64 encoded .pem file using command:

```
openssl x509 -inform der -in server.cer -out server.pem
```

You can print exported certificate to check data using one of the following commands:

```
openssl x509 -in server.cer -noout -text -inform der
openssl x509 -in server.pem -noout -text
```

More `openssl` options can be found at https://www.sslshopper.com/article-most-common-openssl-commands.html

You can also list certificates in keystore using command:

```
keytool -list -keystore keystore.jks
```

Last thing to do is to move **keystore.jks** file to the server's resources (TestSSLServer/src/main/resources/) and **server.cer** to the client's resources (TestSSLClient/src/main/resources).

## Creating certificate for client

If you want to verify client as well during SSL Handshake you have to repeat previous steps for client, creating keystore.jks and exporting client.cer certificate. This time keystore password is set to "ClientKeystorePass" and key password to "ClientKeyPass". You can also give another alias for key.
The new **keystore.jks** file has to be moved to client's resources and **client.cer** file to server's resources.

## Running the test app

Firstly run **AppServer** main class in **TestSSLServer** project, it will open server socket on port 1111 and wait for the incoming connections. Then run **AppClient** main class in **TestSSLClient** project.

If everything goes right, you should see in your **TestSSLServer** console:

```
Listening on port 1111
Accepted connection, starting handshake
Handshake completed
Readed message: Hello server!
Writing response
Closing sockets
```

and in your **TestSSLClient** console:

```
Connecting on port 1111
Socket opened, starting handshake
Handshake completed
Sending message to server
Received response from server: Hello client!
Closing socket
```
