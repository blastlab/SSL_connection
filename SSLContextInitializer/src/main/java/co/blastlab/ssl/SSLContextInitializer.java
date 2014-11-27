package co.blastlab.ssl;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

/**
 * Helper for {@link SSLContext} that allows to easy add keystore
 * and/or trusted certiciates.
 * @author <a href="mailto:mradzikowski@blastlab.co">Maciej Radzikowski</a>
 */
public class SSLContextInitializer {

	private KeyManager[] keyManagers;
	private final KeyStore trustedKeystore;

	public SSLContextInitializer() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
		String keyStoreType = KeyStore.getDefaultType();
		trustedKeystore = KeyStore.getInstance(keyStoreType);
		trustedKeystore.load(null, null);
	}

	/**
	 * Sets keystore used by context.
	 * Keystore keeps private and public key, needed to authenticate this side of connection.
	 * Initializing keystore is critial for using context initialized by {@link #initContext(SSLContext)}
	 * to create {@link SSLServerSocket} or to connect by {@link SSLSocket} as client
	 * but wit client authorization.
	 * @param keystoreIS Keystore Input Stream (.jks file format).
	 * @param keystorePass Password to keystore.
	 * @param certificatePass Password to certificate in keystore.
	 * @throws java.security.KeyStoreException
	 * @throws java.io.IOException
	 * @throws java.security.cert.CertificateException
	 * @throws java.security.NoSuchAlgorithmException
	 * @throws java.security.UnrecoverableKeyException
	 */
	public void setKeystore(InputStream keystoreIS, String keystorePass, String certificatePass) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(keystoreIS, keystorePass.toCharArray());

		KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
		kmf.init(ks, certificatePass.toCharArray());
		keyManagers = kmf.getKeyManagers();
	}

	/**
	 * Adds trusted self-signed certificate used by context.
	 * Self-signed certificates cannot be authenticated, so they must be added manually as trusted
	 * before making a connection. They may be many certificates added.
	 * This is needed to connect to servers that use self-signed certificates by {@link SSLSocket} to make them trusted
	 * or to vertify clients that use self-signed certificates if {@link SSLServerSocket#getNeedClientAuth()} is true.
	 * Add only this certificates that you are completly sure are authentic.
	 * @param alias Unique certificate's alias.
	 * @param certificateIS Input Stream of certificate (.cer/.pem or similar format).
	 * @throws java.security.KeyStoreException
	 * @throws java.security.cert.CertificateException
	 */
	public void addCertificate(String alias, InputStream certificateIS) throws CertificateException, KeyStoreException {
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		Certificate ca = cf.generateCertificate(certificateIS);
		trustedKeystore.setCertificateEntry(alias, ca);
	}

	/**
	 * Initializes context with keystore and/or certificates specified by
	 * {@link #setKeystore(java.io.InputStream, java.lang.String, java.lang.String)} and {@link #addCertificate(java.lang.String, java.io.InputStream)}.
	 * @param sslContext Context to initialize.
	 * @throws java.security.KeyManagementException
	 * @throws java.security.NoSuchAlgorithmException
	 * @throws java.security.KeyStoreException
	 */
	public void initContext(SSLContext sslContext) throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {
		String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
		tmf.init(trustedKeystore);
		TrustManager[] trustManagers = tmf.getTrustManagers();

		sslContext.init(keyManagers, trustManagers, null);
	}

}
