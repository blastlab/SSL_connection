package co.blastlab.ssl;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
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
	private TrustManager[] trustManagers;

	/**
	 * Sets keystore used by context.
	 * Keystore keeps private and public key, needed to authenticate this side of connection.
	 * Initializing keystore is critial for using context initialized by {@link #initContext(SSLContext)}
	 * to create {@link SSLServerSocket} or to connect by {@link SSLSocket} as client
	 * but wit client authorization.
	 * @param keystore Keystore .jks file.
	 * @param keystorePass Password to keystore.
	 * @param certificatePass Password to certificate in keystore.
	 * @throws java.security.KeyStoreException
	 * @throws java.io.IOException
	 * @throws java.security.cert.CertificateException
	 * @throws java.security.NoSuchAlgorithmException
	 * @throws java.security.UnrecoverableKeyException
	 */
	public void setKeystore(File keystore, String keystorePass, String certificatePass) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
		KeyStore ks = KeyStore.getInstance("JKS");

		FileInputStream fis = new FileInputStream(keystore);
		try {
			ks.load(fis, keystorePass.toCharArray());
		} finally {
			fis.close();
		}

		KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
		kmf.init(ks, certificatePass.toCharArray());
		keyManagers = kmf.getKeyManagers();
	}

	/**
	 * Sets trusted self-signed certificates used by context.
	 * Self-signed certificates cannot be authenticated, so they must be added manually as trusted
	 * before making a connection.
	 * This is needed to connect to servers that use self-signed certificates by {@link SSLSocket} to make them trusted
	 * or to vertify clients that use self-signed certificates if {@link SSLServerSocket#getNeedClientAuth()} is true.
	 * Add only this certificates that you are completly sure are authentic.
	 * @param certificates List of certicate .cer/.pem files.
	 * @throws java.security.NoSuchAlgorithmException
	 * @throws java.security.KeyStoreException
	 * @throws java.io.IOException
	 * @throws java.security.cert.CertificateException
	 */
	public void setCertificates(File[] certificates) throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException {
		String keyStoreType = KeyStore.getDefaultType();
		KeyStore keyStore = KeyStore.getInstance(keyStoreType);
		keyStore.load(null, null);

		for (int i = 0; i < certificates.length; i++) {
			addCertificateToKeystore(keyStore, "ca" + i, certificates[i]);
		}

		String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
		tmf.init(keyStore);

		trustManagers = tmf.getTrustManagers();
	}

	private void addCertificateToKeystore(KeyStore keyStore, String alias, File certificate) throws CertificateException, FileNotFoundException, KeyStoreException, IOException {
		CertificateFactory cf = CertificateFactory.getInstance("X.509");

		FileInputStream fis = new FileInputStream(certificate);
		try {
			Certificate ca = cf.generateCertificate(fis);
			keyStore.setCertificateEntry(alias, ca);
		} finally {
			fis.close();
		}
	}

	/**
	 * Initializes context with keystore and/or certificates specified by
	 * {@link #setKeystore(File, String, String)} and {@link #setCertificates(File[])}.
	 * @param sslContext Context to initialize.
	 * @throws java.security.KeyManagementException
	 */
	public void initContext(SSLContext sslContext) throws KeyManagementException {
		sslContext.init(keyManagers, trustManagers, null);
	}

}
