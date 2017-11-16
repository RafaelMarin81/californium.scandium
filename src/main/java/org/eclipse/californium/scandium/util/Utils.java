//: Utils.java
package org.eclipse.californium.scandium.util;

public class Utils {
	/**
	 * Create a 20-row String with the specified content of a buffer (DEBUG)
	 * 
	 * @param buffer		Input buffer
	 * @param pos			Start offset
	 * @param len			Length
	 * @return				A non-empty String
	 */
	public static String asHexCut20(byte[] buffer, int pos, int len) {
		if ((buffer == null) || (buffer.length == 0)) return "";
		
		StringBuilder stringBuilder = new StringBuilder();
		
		byte dato;
		
		for(int count = 0; count < len; count++) {
			if ((count != 0) && ((count % 20) == 0)) {
				stringBuilder.append("\n");
			}
			
			dato = buffer[pos++];
			
			if ((dato >= 0) && (dato <= 15)) {
				stringBuilder.append("0");
			}
			
			stringBuilder.append(Long.toString(((int)dato) & 0x0ff, 16));
			
			if (((count + 1) % 20) != 0) stringBuilder.append(" ");
		}
		
		stringBuilder.append("\n");
		
		return stringBuilder.toString();
	}
}
//:~
