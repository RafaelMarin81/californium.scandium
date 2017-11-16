//: CustomSecureRandom.java
package org.eclipse.californium.scandium.dtls;

import java.security.SecureRandom;

public class CustomSecureRandom extends SecureRandom {
	final static long serialVersionUID = 0L;
	
	public void nextBytes(byte[] bytes) {
//		System.out.printf("CustomSecureRandom/nextBytes: length %d\n", bytes.length);
		
		byte[] arrayTemp = new byte[] {
			(byte)0x4c, (byte)0xbb, (byte)0xf7, (byte)0xf8, (byte)0xe5, (byte)0x96, (byte)0x4b, (byte)0x3c,
			(byte)0xce, (byte)0x30, (byte)0x88, (byte)0x28, (byte)0x6c, (byte)0x25, (byte)0xc9, (byte)0x1f,
			(byte)0x46, (byte)0xd1, (byte)0x10, (byte)0x95, (byte)0x37, (byte)0xbc, (byte)0x98, (byte)0x42,
			(byte)0x74, (byte)0xcd, (byte)0x2a, (byte)0xeb, (byte)0x10, (byte)0xb2, (byte)0x74, (byte)0xa5
		};
		
		for(int i = 0; i < 32; i++) bytes[i] = arrayTemp[31 - i];
	}
}
//:~
