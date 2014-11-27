package co.blastlab.ssl.example;

import co.blastlab.ssl.SSLContextInitializer;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.InputStream;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

public class AppClient {

	private final int PORT = 1111;
	private final String KEYSTORE_FILENAME = "keystore.jks";
	private final String KEYSTORE_PASS = "ClientKeystorePass";
	private final String KEYSTORE_CERT_PASS = "ClientKeyPass";
	private final String SERVER_CERT_FILENAME = "server.cer";

	public static void main(String[] args) throws Exception {
		new AppClient().connectToServer();
	}

	public void connectToServer() throws Exception {
		SSLContextInitializer sci = new SSLContextInitializer();
		
		ClassLoader classLoader = getClass().getClassLoader();
		
		try (InputStream keystoreIS = classLoader.getResourceAsStream(KEYSTORE_FILENAME)) {
			sci.setKeystore(keystoreIS, KEYSTORE_PASS, KEYSTORE_CERT_PASS);
		}
		
		try (InputStream certIS = classLoader.getResourceAsStream(SERVER_CERT_FILENAME)) {
			sci.addCertificate("serverca", certIS);
		}

		SSLContext sc = SSLContext.getInstance("SSL");
		sci.initContext(sc);

		System.out.println("Connecting on port " + PORT);
		try (SSLSocket socket = (SSLSocket) sc.getSocketFactory().createSocket("localhost", PORT)) {
			System.out.println("Socket opened, starting handshake");
			socket.startHandshake(); // execute this method to make sure handshake will be performed before any other communication
			System.out.println("Handshake completed");
			
			DataInputStream in = new DataInputStream(socket.getInputStream());
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			
			System.out.println("Sending message to server");
			out.writeUTF("Hello server!");
			System.out.println("Received response from server: " + in.readUTF());
			
			System.out.println("Closing socket");
		}
	}

}
