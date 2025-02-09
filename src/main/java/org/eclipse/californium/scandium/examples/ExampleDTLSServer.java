/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Matthias Kovatsch - creator and main architect
 *    Stefan Jucker - DTLS implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.examples;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.logging.Level;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.ScandiumLogger;
import org.eclipse.californium.scandium.dtls.pskstore.InMemoryPskStore;



public class ExampleDTLSServer {

	static {
		ScandiumLogger.initialize();
		ScandiumLogger.setLevel(Level.ALL);
	}

//	private static final int DEFAULT_PORT = 5684; 
	private static final int DEFAULT_PORT = 20220; 
	
	private static final String TRUST_STORE_PASSWORD = "rootPass";
	private final static String KEY_STORE_PASSWORD = "endPass";
	private static final String KEY_STORE_LOCATION = "certs/keyStore.jks";
    private static final String TRUST_STORE_LOCATION = "certs/trustStore.jks";
	
	private DTLSConnector dtlsConnector;
	
	// PSK
//	public ExampleDTLSServer() {
//	    InMemoryPskStore pskStore = new InMemoryPskStore();
//        // put in the PSK store the default identity/psk for tinydtls tests
//        pskStore.setKey("Client_identity", "secretPSK".getBytes());
//	   
//	    try {
//	        // load the key store
//	        KeyStore keyStore = KeyStore.getInstance("JKS");
//            InputStream in = new FileInputStream(KEY_STORE_LOCATION);
//            keyStore.load(in, KEY_STORE_PASSWORD.toCharArray());
//
//            // load the trust store
//            KeyStore trustStore = KeyStore.getInstance("JKS");
//            InputStream inTrust = new FileInputStream(TRUST_STORE_LOCATION);
//            trustStore.load(inTrust, TRUST_STORE_PASSWORD.toCharArray());
//            
//            // You can load multiple certificates if needed
//            Certificate[] trustedCertificates = new Certificate[1];
//            trustedCertificates[0] = trustStore.getCertificate("root");
//            
//            dtlsConnector = new DTLSConnector(new InetSocketAddress(InetAddress.getByName("aaaa::1"), DEFAULT_PORT),trustedCertificates);
//            dtlsConnector.getConfig().setPrivateKey((PrivateKey)keyStore.getKey("server", KEY_STORE_PASSWORD.toCharArray()), keyStore.getCertificateChain("server"),true);
//            dtlsConnector.getConfig().setPskStore(pskStore);
//            
//            dtlsConnector.setRawDataReceiver(new RawDataChannelImpl(dtlsConnector));
//
//        } catch (GeneralSecurityException | IOException e) {
//            System.err.println("Could not load the keystore");
//            e.printStackTrace();
//        }
//	 
//	}
	
	// ECC
	public ExampleDTLSServer() {
	    try {
	    	// cargamos el security provider de BouncyCastle
	    	Security.addProvider(new BouncyCastleProvider());
	    	
	    	String keyPath = "/mnt/datos/varios/descargas/secp256r1-key.pem";
	    	BufferedReader br = new BufferedReader(new FileReader(keyPath));
	    	
	    	PEMParser pp = new PEMParser(br);
	    	PEMKeyPair pemKeyPair = (PEMKeyPair) pp.readObject();
	    	pp.close();
	    	
	    	KeyPair kp = new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
	    	PrivateKey privateKey = kp.getPrivate();
	    	PublicKey publicKey = kp.getPublic();
	    	
	    	BCECPrivateKey bcePrivateKey = (BCECPrivateKey)privateKey;
	    	BCECPublicKey bcePublicKey = (BCECPublicKey)publicKey;
	    	
	    	System.out.printf("privateKey: %s algorithm %s format %s key %s - S %s\n", privateKey.getClass(), privateKey.getAlgorithm(), privateKey.getFormat(), privateKey.toString(),
	    		((ECPrivateKey)privateKey).getS().toString());
	    	System.out.printf("    fieldSize %d\n", bcePrivateKey.getParameters().getCurve().getFieldSize());
	    	System.out.printf("publicKey: %s algorithm %s format %s key %s - W(x) %s W(y) %s\n", publicKey.getClass(), publicKey.getAlgorithm(), publicKey.getFormat(), publicKey.toString(),
	    		((ECPublicKey)publicKey).getW().getAffineX().toString(), ((ECPublicKey)publicKey).getW().getAffineY().toString());
	    	System.out.printf("    fieldSize %d\n", bcePublicKey.getParameters().getCurve().getFieldSize());
	    	
	        // load the key store
	        KeyStore keyStore = KeyStore.getInstance("JKS");
            InputStream in = new FileInputStream(KEY_STORE_LOCATION);
            keyStore.load(in, KEY_STORE_PASSWORD.toCharArray());

            // load the trust store
            KeyStore trustStore = KeyStore.getInstance("JKS");
            InputStream inTrust = new FileInputStream(TRUST_STORE_LOCATION);
            trustStore.load(inTrust, TRUST_STORE_PASSWORD.toCharArray());
            
            // You can load multiple certificates if needed
            Certificate[] trustedCertificates = new Certificate[1];
            trustedCertificates[0] = trustStore.getCertificate("root");
            
            dtlsConnector = new DTLSConnector(new InetSocketAddress(InetAddress.getByName("aaaa::1"), DEFAULT_PORT), /*trustedCertificates*/ null);
            dtlsConnector.getConfig().setPrivateKey(privateKey, publicKey);
            dtlsConnector.getConfig().setRequireClientAuth(false);
            
            dtlsConnector.setRawDataReceiver(new RawDataChannelImpl(dtlsConnector));

        } catch (GeneralSecurityException | IOException e) {
            System.err.println("Could not load the keystore");
            e.printStackTrace();
        }
	 
	}
	
	public void start() {
		try {
			dtlsConnector.start();
		} catch (IOException e) {
			throw new IllegalStateException("Unexpected error starting the DTLS UDP server",e);
		}
	}
	
	private class RawDataChannelImpl implements RawDataChannel {
		
		private Connector connector;
		
		public RawDataChannelImpl(Connector con) {
			this.connector = con;
		}

		// @Override
		public void receiveData(final RawData raw) {
			if (raw.getAddress() == null)
				throw new NullPointerException();
			if (raw.getPort() == 0)
				throw new NullPointerException();
			
			System.out.println(new String(raw.getBytes()));
			connector.send(new RawData("ACK".getBytes(), raw.getAddress(), raw.getPort()));
		}
	}
	
	public static void main(String[] args) {
		
		ExampleDTLSServer server = new ExampleDTLSServer();
		server.start();
		
		try {
			System.in.read();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
