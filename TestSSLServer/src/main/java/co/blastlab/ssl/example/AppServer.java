package co.blastlab.ssl.example;

import co.blastlab.ssl.SSLContextInitializer;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.InputStream;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

public class AppServer {

	private final int PORT = 1111;
	private final String KEYSTORE_FILENAME = "keystore.jks";
	private final String KEYSTORE_PASS = "ServerKeystorePass";
	private final String KEYSTORE_CERT_PASS = "ServerKeyPass";
	private final String CLIENT_CERT_FILENAME = "client.cer";

	public static void main(String[] args) throws Exception {
		new AppServer().openSocket();
	}

	public void openSocket() throws Exception {
		SSLContextInitializer sci = new SSLContextInitializer();

		ClassLoader classLoader = getClass().getClassLoader();

		try (InputStream keystoreIS = classLoader.getResourceAsStream(KEYSTORE_FILENAME)) {
			sci.setKeystore(keystoreIS, KEYSTORE_PASS, KEYSTORE_CERT_PASS);
		}

		try (InputStream certIS = classLoader.getResourceAsStream(CLIENT_CERT_FILENAME)) {
			sci.addCertificate("clientca", certIS);
		}

		SSLContext sc = SSLContext.getInstance("SSL");
		sci.initContext(sc);

		try (SSLServerSocket server = (SSLServerSocket) sc.getServerSocketFactory().createServerSocket(PORT)) {
			server.setNeedClientAuth(true);
			System.out.println("Listening on port " + PORT);
			
			try (SSLSocket socket = (SSLSocket) server.accept()) {
				System.out.println("Accepted connection, starting handshake");
				socket.startHandshake();
				System.out.println("Handshake completed");
				
				DataInputStream in = new DataInputStream(socket.getInputStream());
				DataOutputStream out = new DataOutputStream(socket.getOutputStream());
				
				System.out.println("Readed message: " + in.readUTF());
				System.out.println("Writing response");
				out.writeUTF("Hello client!");
				
				System.out.println("Closing sockets");
			}
		}
	}

}
