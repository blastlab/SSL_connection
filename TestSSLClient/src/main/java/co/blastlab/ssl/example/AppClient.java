package co.blastlab.ssl.example;

import co.blastlab.ssl.SSLContextInitializer;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
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
		ClassLoader classLoader = getClass().getClassLoader();
		File keystoreFile = new File(classLoader.getResource(KEYSTORE_FILENAME).getFile());
		File serverCertFile = new File(classLoader.getResource(SERVER_CERT_FILENAME).getFile());

		SSLContextInitializer sci = new SSLContextInitializer();
		sci.setKeystore(keystoreFile, KEYSTORE_PASS, KEYSTORE_CERT_PASS);
		sci.setCertificates(new File[]{serverCertFile});

		SSLContext sc = SSLContext.getInstance("SSL");
		sci.initContext(sc);

		System.out.println("Connecting on port " + PORT);
		SSLSocket socket = (SSLSocket) sc.getSocketFactory().createSocket("localhost", PORT);
		System.out.println("Socket opened, starting handshake");
		socket.startHandshake(); // execute this method to make sure handshake will be performed before any other communication
		System.out.println("Handshake completed");

		DataInputStream in = new DataInputStream(socket.getInputStream());
		DataOutputStream out = new DataOutputStream(socket.getOutputStream());

		System.out.println("Sending message to server");
		out.writeUTF("Hello server!");
		System.out.println("Received response from server: " + in.readUTF());

		System.out.println("Closing socket");
		socket.close();
	}

}
