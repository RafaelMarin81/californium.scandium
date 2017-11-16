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
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.Base64;
import java.util.logging.Level;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.ScandiumLogger;
import org.eclipse.californium.scandium.dtls.CustomSecureRandom;
import org.eclipse.californium.scandium.dtls.Random;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm;
import org.eclipse.californium.scandium.dtls.CertificateRequest.HashAlgorithm;
import org.eclipse.californium.scandium.dtls.CertificateRequest.SignatureAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.ECDHECryptography;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;


public class ExampleDTLSClient {

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
//	public ExampleDTLSClient() {
//	    try {
//	        // load key store
//            KeyStore keyStore = KeyStore.getInstance("JKS");
//            InputStream in = new FileInputStream(KEY_STORE_LOCATION);
//            keyStore.load(in, KEY_STORE_PASSWORD.toCharArray());
//    
//            // load trust store
//            KeyStore trustStore = KeyStore.getInstance("JKS");
//            InputStream inTrust = new FileInputStream(TRUST_STORE_LOCATION);
//            trustStore.load(inTrust, TRUST_STORE_PASSWORD.toCharArray());
//            
//            // You can load multiple certificates if needed
//            Certificate[] trustedCertificates = new Certificate[1];
//            trustedCertificates[0] = trustStore.getCertificate("root");
//    
//    		dtlsConnector = new DTLSConnector(new InetSocketAddress(0), trustedCertificates);
//    		dtlsConnector.getConfig().setPskStore(new StaticPskStore("Client_identity", "secretPSK".getBytes()));
// //   		dtlsConnector.getConfig().setPrivateKey((PrivateKey)keyStore.getKey("client", KEY_STORE_PASSWORD.toCharArray()), keyStore.getCertificateChain("client"), true);
//    		
//    		dtlsConnector.setRawDataReceiver(new RawDataChannelImpl());
//    		
//	    } catch (GeneralSecurityException | IOException e) {
//            System.err.println("Could not load the keystore");
//            e.printStackTrace();
//        }
//	}
	
	/**
	 * Create a C-ready BYTE array in String format (DEBUG)
	 * 
	 * @param name			Var name
	 * @param buffer		Input buffer
	 * @return				The String ready to paste into a C program
	 */
	public static String showArrayBytes(String name, byte[] buffer) {
		StringBuilder stringBuilder = new StringBuilder();
		
		stringBuilder.append("const BYTE ");
		stringBuilder.append(name);
		stringBuilder.append("[");
		stringBuilder.append(buffer.length);
		stringBuilder.append("] = {\n\t");
		
		byte dato, hi, lo;
		
		for(int i = 0; i < buffer.length;) {
			if ((i != 0) && ((i % 20) == 0)) {
				stringBuilder.append(",\n\t");
			}
			else if (i != 0) {
				stringBuilder.append(", ");
			}
			
			stringBuilder.append("0x");
			
			dato = buffer[i++];
			
			hi = (byte)((dato >> 4) & 0x0F);
			
			if (hi >= 10) {
				stringBuilder.append(Character.toString((char)('A' + (hi - 10))));
			}
			else {
				stringBuilder.append(Character.toString((char)('0' + hi)));
			}
			
			lo = (byte)(dato & 0x0F);
			
			if (lo >= 10) {
				stringBuilder.append(Character.toString((char)('A' + (lo - 10))));
			}
			else {
				stringBuilder.append(Character.toString((char)('0' + lo)));
			}
		}
		
		stringBuilder.append("\n};\n");
		
		return stringBuilder.toString();
	}
	
	/**
	 * Codifica en DER/Base64 las 2 coordenadas de un punto de una curva
	 * 
	 * @param coordX		La coordenada X
	 * @param coordY		La coordenada Y
	 * @return				El resultado de codificarlas en DER y luego pasarlas a Base64
	 */
	public static String encodeToDerInBase64(BigInteger coordX, BigInteger coordY) {
		byte[] arrayX = coordX.toByteArray();
		byte[] arrayY = coordY.toByteArray();
		
		/* 0x30 b1 0x02 b2 (vr) 0x02 b3 (vs)
		 * 
		 * b1 = longitud de los bytes que van despu&eacute;s suyo (los 2 0x02, b2, b3, vr.length y vs.length)
		 * b2 = vr.length
		 * b3 = vs.length
		 */
		byte[] buffer = new byte[arrayX.length + arrayY.length + 6];
		
		int offset = 0;
		
		// cabecera
		buffer[offset++] = (byte)0x30;
		buffer[offset++] = (byte)(4 + arrayX.length + arrayY.length);
		buffer[offset++] = (byte)0x02;
		buffer[offset++] = (byte)arrayX.length;
		
		// coordenada X
		System.arraycopy(arrayX, 0, buffer, offset, arrayX.length);
		
		offset += arrayX.length;
		
		buffer[offset++] = (byte)0x02;
		buffer[offset++] = (byte)arrayY.length;
		
		// coordenada Y
		System.arraycopy(arrayY, 0, buffer, offset, arrayY.length);
		
		System.out.printf("clave encoded v1 %s\n", showArrayBytes("v1", buffer));
		
		return Base64.getEncoder().encodeToString(buffer);
	}
	
	// ECC
	@SuppressWarnings("deprecation")
	public ExampleDTLSClient() {
	    try {
	    	String input = "CapabilityToken{id=8tkf0lkpirv3ue0tef50agfdsq, ii=1457110896, is=issuer, su=AKDB/EtV2FRCe13hthPprvLpCX3fi0NkYixjLRVBSXWRfyRqxyhC9ImUjtYtix0QxY9nVEocvbeIr6e70GiBhKI=, de=device, ar=; SimpleAccessRight{ac=action, re=resource}, nb=1457110896, na=1457111896}";
	    	String si = "MEUCIQCsPytuqVme0uo4kSJGM5UjUsFK3DZc1WEuYYn+8YZAIQIgG1Ei+fZNZBrdmEP3oC7Z6UnK1FwFYCDAIxaeveBYO4w=";
	    	
	    	byte[] decoded = Base64.getDecoder().decode(si);
	    	
	    	// cargamos el security provider de BouncyCastle
	    	Security.addProvider(new BouncyCastleProvider());
	    	
	    	String keyPath = "/mnt/datos/varios/descargas/secp256r1-key2.pem";
	    	BufferedReader br = new BufferedReader(new FileReader(keyPath));
	    	
	    	PEMParser pp = new PEMParser(br);
	    	PEMKeyPair pemKeyPair = (PEMKeyPair) pp.readObject();
	    	pp.close();
	    	
	    	KeyPair kp = new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
	    	PrivateKey privateKey = kp.getPrivate();
	    	PublicKey publicKey = kp.getPublic();
	    	
	    	String encodedOriginalPublic = Base64.getEncoder().encodeToString(publicKey.getEncoded());
	    	System.out.printf("FULL-BASE64:\n%s\n", encodedOriginalPublic);
	    	
	    	BCECPrivateKey bcePrivateKey = (BCECPrivateKey)privateKey;
	    	BCECPublicKey bcePublicKey = (BCECPublicKey)publicKey;
	    	
	    	System.out.printf("privateKey: %s algorithm %s format %s key %s\n\n", privateKey.getClass(), privateKey.getAlgorithm(), privateKey.getFormat(), privateKey.toString());
	    	System.out.printf("    fieldSize %d\n", bcePrivateKey.getParameters().getCurve().getFieldSize());
	    	System.out.printf("publicKey: %s algorithm %s format %s key %s\n", publicKey.getClass(), publicKey.getAlgorithm(), publicKey.getFormat(), publicKey.toString());
	    	System.out.printf("    fieldSize %d\n", bcePublicKey.getParameters().getCurve().getFieldSize());
	    	
	    	String keyBase64 = encodeToDerInBase64(bcePublicKey.getW().getAffineX(), bcePublicKey.getW().getAffineY());
	    	
	    	System.out.printf("keyBase64:\n%s\n", keyBase64);
	    	
	    	byte[] arrayX = bcePublicKey.getW().getAffineX().toByteArray();
	    	byte[] arrayY = bcePublicKey.getW().getAffineY().toByteArray();
	    	
	    	byte[] combinado = new byte[arrayX.length + arrayY.length];
	    	
	    	System.arraycopy(arrayX, 0, combinado, 0, arrayX.length);
	    	System.arraycopy(arrayY, 0, combinado, arrayX.length, arrayY.length);
	    	
	    	String claveEncoded = Base64.getEncoder().encodeToString(combinado);
	    	
	    	System.out.printf("clave encoded %s\n", claveEncoded);
	    	
	    	byte[] publicKeyEncoded = bcePublicKey.getEncoded();
	    	
	    	System.out.printf("clave encoded v2 %s\n", showArrayBytes("v2", publicKeyEncoded));
	    	
			Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
			ecdsaVerify.initVerify(kp.getPublic());
			ecdsaVerify.update(input.getBytes("UTF-8"));
			boolean result = ecdsaVerify.verify(decoded);
			
			System.out.printf("ok %b\n", result);	// <- FALSE
	    	
			Signature signer = Signature.getInstance("SHA256withECDSA", "BC");
			signer.initSign(kp.getPrivate(), new SecureRandom());
			
			signer.update(input.getBytes());
			byte[] sigBytes = signer.sign();
			
			ecdsaVerify.initVerify(kp.getPublic());
			ecdsaVerify.update(input.getBytes("UTF-8"));
			result = ecdsaVerify.verify(sigBytes);
			
			System.out.printf("ok %b\n", result);	// <- TRUE (obviamente)
			
			String encoded = Base64.getEncoder().encodeToString(sigBytes);
			System.out.printf("encoded: %s\n", encoded);
			

			
//	    	byte[] clientRandom = new byte[] {
//	    		(byte)0x56, (byte)0x3c, (byte)0x7b, (byte)0xcf, (byte)0xd4, (byte)0x44, (byte)0x40, (byte)0x83,
//	    		(byte)0xd1, (byte)0x9f, (byte)0x7e, (byte)0x8e, (byte)0x41, (byte)0xe5, (byte)0x66, (byte)0x52,
//	    		(byte)0x60, (byte)0xf8, (byte)0xdc, (byte)0xe7,	(byte)0x9f, (byte)0x59, (byte)0xd3, (byte)0xe7,
//	    		(byte)0xb6, (byte)0x8c, (byte)0xbf, (byte)0x68, (byte)0x12, (byte)0xdd, (byte)0x51, (byte)0xd8
//	    	};
//	    	
//	    	byte[] serverRandom = new byte[] {
//    			(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x83, (byte)0xb4, (byte)0x19, (byte)0x08,
//    			(byte)0x6b, (byte)0x68, (byte)0xe4, (byte)0xf1, (byte)0xad, (byte)0x1c, (byte)0x5b, (byte)0x69,
//    			(byte)0x7d, (byte)0xdb, (byte)0x5e, (byte)0x5e, (byte)0x52, (byte)0xc3, (byte)0x81, (byte)0xae,
//    			(byte)0x59, (byte)0x4b, (byte)0x4b, (byte)0x92, (byte)0xf0, (byte)0x2a, (byte)0x5f, (byte)0xf1
//	    	};
//	    	
//	    	byte[] keyxparams = new byte[] {
//    			(byte)0x03, (byte)0x00, (byte)0x17, (byte)0x41, (byte)0x04, (byte)0x94, (byte)0xef, (byte)0x69,
//    			(byte)0x15, (byte)0x52, (byte)0x8a, (byte)0x49, (byte)0xfc, (byte)0x17, (byte)0xcc, (byte)0x09,
//    			(byte)0xf7, (byte)0x18, (byte)0x51, (byte)0xd4, (byte)0x72, (byte)0xb2, (byte)0x75, (byte)0x89,
//    			(byte)0x2d, (byte)0x38, (byte)0x0e, (byte)0x17, (byte)0xbd, (byte)0x84, (byte)0x11, (byte)0xb6,
//    			(byte)0xf3, (byte)0x56, (byte)0xa6, (byte)0xa9, (byte)0xd0, (byte)0xf5, (byte)0xa1, (byte)0xd1,
//    			(byte)0xa3, (byte)0xe1, (byte)0x09, (byte)0x16, (byte)0xab, (byte)0xd5, (byte)0x2d, (byte)0x41,
//    			(byte)0x86, (byte)0xca, (byte)0xaf, (byte)0xed, (byte)0x1c, (byte)0x59, (byte)0x77, (byte)0xcf,
//    			(byte)0x8f, (byte)0xf6, (byte)0xc4, (byte)0xe2, (byte)0x35, (byte)0x02, (byte)0x68, (byte)0x63,
//    			(byte)0x90, (byte)0x07, (byte)0x9a, (byte)0x9d, (byte)0x2c
//	    	};
//	    	
//	    	byte[] combo = new byte[clientRandom.length + serverRandom.length + keyxparams.length];
//	    	
//	    	int offset = 0;
//	    	System.arraycopy(clientRandom, 0, combo, offset, clientRandom.length);
//	    	offset += clientRandom.length;
//	    	
//	    	System.arraycopy(serverRandom, 0, combo, offset, serverRandom.length);
//	    	offset += serverRandom.length;
//	    	
//	    	System.arraycopy(keyxparams, 0, combo, offset, keyxparams.length);
//	    	
//	    	System.out.printf("%s\n", showArrayBytes("DATA", combo));
//	    	
//	    	byte[] r = new byte[] {
//    			(byte)0x8c, (byte)0x56, (byte)0x7b, (byte)0x29, (byte)0x63, (byte)0xe6, (byte)0x54, (byte)0x27,
//    			(byte)0xef, (byte)0xfa, (byte)0x99, (byte)0xa6, (byte)0xb8, (byte)0xa4, (byte)0xcc, (byte)0xfd,
//    			(byte)0x1f, (byte)0xc2, (byte)0x5e, (byte)0x12, (byte)0xbe, (byte)0x3f, (byte)0x08, (byte)0xa6,
//    			(byte)0x17, (byte)0x01, (byte)0xd6, (byte)0xa8, (byte)0x85, (byte)0x8d, (byte)0xb7, (byte)0x9c,	
//	    	};
//	    	
//	    	byte[] s = new byte[] {
//    			(byte)0x4d, (byte)0x65, (byte)0x6b, (byte)0x85, (byte)0x6f, (byte)0x6a, (byte)0x41, (byte)0x2a,
//    			(byte)0xa4, (byte)0x1c, (byte)0xfe, (byte)0xf7, (byte)0x49, (byte)0xb6, (byte)0x40, (byte)0xbb,
//    			(byte)0xca, (byte)0x57, (byte)0xc0, (byte)0xb3, (byte)0x83, (byte)0xd4, (byte)0x56, (byte)0x7b,
//    			(byte)0x7f, (byte)0x5b, (byte)0x90, (byte)0x8a, (byte)0xb1, (byte)0x6a, (byte)0x86, (byte)0xb2
//	    	};
//	    	
//	    	System.out.printf("%s\n", showArrayBytes("R", r));
//	    	
//	    	System.out.printf("%s\n", showArrayBytes("S", s));
//	    	
//	    	byte[] signature = new byte[] {
//    			(byte)0x30, (byte)0x45,
//    			(byte)0x02, (byte)0x21, (byte)0x00,
//    			(byte)0x8c, (byte)0x56, (byte)0x7b, (byte)0x29, (byte)0x63, (byte)0xe6, (byte)0x54, (byte)0x27,
//    			(byte)0xef, (byte)0xfa, (byte)0x99, (byte)0xa6, (byte)0xb8, (byte)0xa4, (byte)0xcc, (byte)0xfd,
//    			(byte)0x1f, (byte)0xc2, (byte)0x5e, (byte)0x12, (byte)0xbe, (byte)0x3f, (byte)0x08, (byte)0xa6,
//    			(byte)0x17, (byte)0x01, (byte)0xd6, (byte)0xa8, (byte)0x85, (byte)0x8d, (byte)0xb7, (byte)0x9c,
//    			(byte)0x02, (byte)0x20,
//    			(byte)0x4d, (byte)0x65, (byte)0x6b, (byte)0x85, (byte)0x6f, (byte)0x6a, (byte)0x41, (byte)0x2a,
//    			(byte)0xa4, (byte)0x1c, (byte)0xfe, (byte)0xf7, (byte)0x49, (byte)0xb6, (byte)0x40, (byte)0xbb,
//    			(byte)0xca, (byte)0x57, (byte)0xc0, (byte)0xb3, (byte)0x83, (byte)0xd4, (byte)0x56, (byte)0x7b,
//    			(byte)0x7f, (byte)0x5b, (byte)0x90, (byte)0x8a, (byte)0xb1, (byte)0x6a, (byte)0x86, (byte)0xb2
//	    	};
//	    	
//			Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
//			ecdsaVerify.initVerify(publicKey);
//			ecdsaVerify.update(clientRandom);
//			ecdsaVerify.update(serverRandom);
//			ecdsaVerify.update(keyxparams);
//			
//			boolean result = ecdsaVerify.verify(signature);
//			
//			System.out.printf("OK %b\n", result);
	    	
//	        // load key store
//            KeyStore keyStore = KeyStore.getInstance("JKS");
//            InputStream in = new FileInputStream(KEY_STORE_LOCATION);
//            keyStore.load(in, KEY_STORE_PASSWORD.toCharArray());
//    
//            // load trust store
//            KeyStore trustStore = KeyStore.getInstance("JKS");
//            InputStream inTrust = new FileInputStream(TRUST_STORE_LOCATION);
//            trustStore.load(inTrust, TRUST_STORE_PASSWORD.toCharArray());
//            
//            // You can load multiple certificates if needed
//            Certificate[] trustedCertificates = new Certificate[1];
//            trustedCertificates[0] = trustStore.getCertificate("root");
    
    		dtlsConnector = new DTLSConnector(new InetSocketAddress(0));
    		dtlsConnector.getConfig().setPrivateKey(privateKey, publicKey);
    		
    		dtlsConnector.setRawDataReceiver(new RawDataChannelImpl());
    		
	    } catch (Exception e) {
            System.err.println("Could not load the keystore");
            e.printStackTrace();
        }
	}
	
	public void test() {
		try {
			dtlsConnector.start();
//			dtlsConnector.send(new RawData("HELLO WORLD".getBytes(), InetAddress.getByName("155.54.171.164") , DEFAULT_PORT));
			dtlsConnector.send(new RawData("HELLO WORLD".getBytes(), InetAddress.getByName("aaaa::2") , DEFAULT_PORT));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	private class RawDataChannelImpl implements RawDataChannel {

		// @Override
		public void receiveData(final RawData raw) {
			
			System.out.println(new String(raw.getBytes()));
			
			try {
				dtlsConnector.close(new InetSocketAddress(InetAddress.getByName("192.168.1.108") , DEFAULT_PORT));
//				dtlsConnector.close(new InetSocketAddress(InetAddress.getByName("aaaa::3") , DEFAULT_PORT));
			} catch(Exception ex) {
				ex.printStackTrace();
			}
			
			// notify main thread to exit
			synchronized (ExampleDTLSClient.class) {
				ExampleDTLSClient.class.notify();
			}
		}
	}
	
	public static void main(String[] args) throws InterruptedException {
		
		ExampleDTLSClient client = new ExampleDTLSClient();
		client.test();
		
		// Connector threads run as daemons so wait in main thread until handshake is done
		synchronized (ExampleDTLSClient.class) {
			ExampleDTLSClient.class.wait();
		}
	}
}
