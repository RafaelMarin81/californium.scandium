package odins.ezequiel.dtlsproxy;


import java.net.InetSocketAddress;
import java.util.HashMap;
import java.io.IOException;
import javax.xml.bind.DatatypeConverter;


/**
 * Created by Ezequiel on 25/01/16.
 * Modified by Rafa on 1/09/17.
 */
public class DTLSProxy {

    final private static HashMap<Integer, DTLSSocket> dtlsSocketTable = new HashMap<Integer, DTLSSocket>();
    final private static HashMap<Integer, UDPSocket> udpSocketTable = new HashMap<Integer, UDPSocket>();
	
    private static final int DEFAULT_LOCAL_PORT_DTLS = 40000; //20220;							// puerto DTLS del lado del proxy
    //private static final String DEFAULT_REMOTE_ADDRESS_DTLS = "aaaa::3";		// dirección Mota
//    private static final int DEFAULT_REMOTE_PORT_DTLS = 40000; //20220;					// puerto local servidor CoAP Mota

    private static final int DEFAULT_PORT_UDP = 50000; //5684;							// puerto escucha del proxy (parte sin DTLS)

    private static final String DEFAULT_REMOTE_ADDRESS_UDP = "aaaa::1";	        // dirección IoT-Agent
    private static final int DEFAULT_REMOTE_PORT_UDP = 5683;					// puerto de escucha del IoT-Agent

    private static final int DTLS_COAP_DEFAULT_PORT = 5684;			// Puerto de escucha de Motes

    public static void main(String[] in) throws IOException {
    	System.out.printf("Dynamic DTLSProxy/main: OK  2017\n");
    	
    	createControllerUDPSocket();	// Dynamic DTLS-Proxy for UDP command from IoT-Controller.
    	
    	//createDynamicDTLSProxy(String remoteAddressDtls, int portDTLS, int portUDP, String PEMK_key)
    	createDynamicDTLSProxy("aaaa::2", 40002, 50002, "secretPSK");
    	createDynamicDTLSProxy("aaaa::2", 40003, 50003, "secretPSK");
    	//createDynamicDTLSProxy("aaaa::2", 40002, 50002, "6188C41313341202007BE5003A000256");
    	//createDynamicDTLSProxy("aaaa::2", 40002, 50002, "6188C41313341202");
    	
    	
    	//createDTLSProxy("aaaa::2", DEFAULT_LOCAL_PORT_DTLS+2, DEFAULT_PORT_UDP+2);
    	//createDTLSProxy("aaaa::2", DEFAULT_LOCAL_PORT_DTLS+3, DEFAULT_PORT_UDP+3);
    	
    	/*createDTLSProxy("aaaa::3", DEFAULT_LOCAL_PORT_DTLS+3, DEFAULT_PORT_UDP+3);
    	createDTLSProxy("aaaa::4", DEFAULT_LOCAL_PORT_DTLS+4, DEFAULT_PORT_UDP+4);
    	createDTLSProxy("aaaa::5", DEFAULT_LOCAL_PORT_DTLS+5, DEFAULT_PORT_UDP+5);
    	createDTLSProxy("aaaa::6", DEFAULT_LOCAL_PORT_DTLS+6, DEFAULT_PORT_UDP+6);
    	createDTLSProxy("aaaa::7", DEFAULT_LOCAL_PORT_DTLS+7, DEFAULT_PORT_UDP+7);
    	createDTLSProxy("aaaa::8", DEFAULT_LOCAL_PORT_DTLS+8, DEFAULT_PORT_UDP+8);
    	createDTLSProxy("aaaa::9", DEFAULT_LOCAL_PORT_DTLS+9, DEFAULT_PORT_UDP+9);*/

    }

    public static void createControllerUDPSocket() throws IOException {
    	
        DynamicProxyController proxyController = new DynamicProxyController(DEFAULT_PORT_UDP);

        proxyController.addSocketListener(new SocketListener() {
            @Override
            public void onData(byte[] data, int len, InetSocketAddress address) {
            	try {
            		String sentence = new String(data, 0, len);
                    System.out.println("RECEIVED " + len + " bytes: " + sentence);
                    
                    //byte [] data = sentence.getBytes();
                    // Node_id is 4 bytes from 35 to 39 
                    //byte[] NodeID = Arrays.copyOfRange(data, 35, 39);
                    //String NodeID = sentence.substring(35,39);
                    String NodeID = sentence.substring(28,32);
                    // Full IPv6 address is 39 bytes from 0 to 39 
                    //byte[] IPv6Mote = Arrays.copyOfRange(data, 0, 39);
                    String IPv6Mote = sentence.substring(0,4);
                    for (int i = 1; i < 8; i++) {
                    	IPv6Mote = IPv6Mote + ":" + sentence.substring((i*4) , ((i*4)+4));
                	}
                                        
                    // PEMK key is 32 characters
                    //byte[] PEMK_key = Arrays.copyOfRange(data, 39, 71);
                    //String PEMK_key = sentence.substring(39,71);
                    //String PEMK_key = sentence.substring(32,48);
                    String PEMK_key_HexString = sentence.substring(32,64);		// TODO: 64 bytes
                    byte[] PEMK_key_ByteArray = HexStringtoByteArray(PEMK_key_HexString);
                    
                    
                    System.out.println("NODE_ID: "+NodeID);
                    System.out.println("IPv6Mote: "+IPv6Mote);
                    System.out.println("PEMK_key_HexString: "+PEMK_key_HexString);
                    System.out.println("PEMK_key_ByteArray: "+PEMK_key_ByteArray.toString());
                    

                    int nodeID_integer = Integer.parseInt(NodeID, 16);
                    System.out.println("nodeID_integer: "+nodeID_integer);
                    
                    createDynamicDTLSProxy(IPv6Mote, DEFAULT_LOCAL_PORT_DTLS + nodeID_integer, 50000 + nodeID_integer, PEMK_key_ByteArray);
					//createDynamicDTLSProxy("aaaa::2", 40002, 50002, "6188C41313341202".getBytes());
                    //createDynamicDTLSProxy(IPv6Mote, 40000 + nodeID_integer, 50000 + nodeID_integer, PEMK_key);
				} catch (IOException e) {
					// Auto-generated catch block
					e.printStackTrace();
				}
            }
        });
        
        proxyController.accept();
    }

    public static void createDynamicDTLSProxy(String remoteAddressDtls, int portDTLS, int portUDP, String PEMK_key) throws IOException {
    	createDynamicDTLSProxy(remoteAddressDtls, portDTLS, portUDP, PEMK_key.getBytes());
    }
    
    public static void createDynamicDTLSProxy(String remoteAddressDtls, int portDTLS, int portUDP, byte[] PEMK_key) throws IOException {
        final String DEFAULT_REMOTE_ADDRESS_UDP = "aaaa::1";	        // dirección IoT-Agent
        final int DEFAULT_REMOTE_PORT_UDP = 5683;				// puerto de escucha del IoT-Agent
        
    	// port out of range:94833
        if((portDTLS > 0xFFFF) || (portUDP > 0xFFFF) || (portDTLS < 1024) || (portDTLS < 1024)) {
        	System.err.printf("createDynamicDTLSProxy: ERROR  Maximum port 65535. FAILED portDTLS: "+portDTLS+" portUDP: "+portUDP+"\n");
        	return;
        }
        
        DTLSSocket oldDTLSSocket = dtlsSocketTable.get(new Integer(portDTLS));
        if (oldDTLSSocket != null) {
        	oldDTLSSocket.close();
        } 
        
        UDPSocket oldUDPSocket = udpSocketTable.get(new Integer(portUDP));;
        if (oldUDPSocket != null) {
        	oldUDPSocket.close();   
        	
        } 
        
        final DTLSSocket dtlsSocket = new DTLSSocket(portDTLS, PEMK_key);
        final UDPSocket udpSocket = new UDPSocket(portUDP);
        final CoapForwardTable ft = new CoapForwardTable();
        
        ft.setDefaultForwardingAddress(new InetSocketAddress(DEFAULT_REMOTE_ADDRESS_UDP, DEFAULT_REMOTE_PORT_UDP));
        dtlsSocket.addSocketListener(new SocketListener() {
            @Override
            public void onData(byte[] data, int len, InetSocketAddress address) {
            	dtlsSocket.changeAddressing(address);	// Establish the default addr+port from the device that is connected.
                udpSocket.changeAddressing(ft.outgoingPacket(address, data));
                udpSocket.send(data, len);
            }
        });
        udpSocket.addSocketListener(new SocketListener() {
            @Override
            public void onData(byte[] data, int len, InetSocketAddress address) {
                ft.incomingPacket(address, data);
                dtlsSocket.send(data, len);
            }
        });
        
        dtlsSocket.setInitialRemote(remoteAddressDtls, DTLS_COAP_DEFAULT_PORT); // All devices listen on DEFAULT_LOCAL_PORT_DTLS 
        udpSocket.setInitialRemote(DEFAULT_REMOTE_ADDRESS_UDP, DEFAULT_REMOTE_PORT_UDP);

        dtlsSocket.accept();
        udpSocket.accept();
        
        dtlsSocketTable.put(new Integer(portDTLS), dtlsSocket);
        udpSocketTable.put(new Integer(portUDP), udpSocket);
        
/*        udpSocket.close();
        dtlsSocket.close();*/
        
    }    
    
    public static void createDTLSProxy(String remoteAddressDtls, int portDTLS, int portUDP) throws IOException {
    	
        final DTLSSocket dtlsSocket = new DTLSSocket(portDTLS); //PORT_DTLS);
        final UDPSocket udpSocket = new UDPSocket(portUDP); //PORT_UDP);
        final CoapForwardTable ft = new CoapForwardTable();
        ft.setDefaultForwardingAddress(new InetSocketAddress(DEFAULT_REMOTE_ADDRESS_UDP, DEFAULT_REMOTE_PORT_UDP));
        dtlsSocket.addSocketListener(new SocketListener() {
            @Override
            public void onData(byte[] data, int len, InetSocketAddress address) {
            	dtlsSocket.changeAddressing(address);	// Establish the default addr+port from the device that is connected.
                udpSocket.changeAddressing(ft.outgoingPacket(address, data));
                udpSocket.send(data, len);
            }
        });
        udpSocket.addSocketListener(new SocketListener() {
            @Override
            public void onData(byte[] data, int len, InetSocketAddress address) {
                ft.incomingPacket(address, data);
                dtlsSocket.send(data, len);
            }
        });

        dtlsSocket.setInitialRemote(remoteAddressDtls, DTLS_COAP_DEFAULT_PORT); // All devices listen on DEFAULT_LOCAL_PORT_DTLS
//        dtlsSocket.setInitialRemote(REMOTE_ADDRESS_DTLS, REMOTE_PORT_DTLS);
        udpSocket.setInitialRemote(DEFAULT_REMOTE_ADDRESS_UDP, DEFAULT_REMOTE_PORT_UDP);

        dtlsSocket.accept();
        udpSocket.accept();
    }
    

    public static String ByteArraytoHexString(byte[] array) {
        return DatatypeConverter.printHexBinary(array);
    }

    public static byte[] HexStringtoByteArray(String s) {
        return DatatypeConverter.parseHexBinary(s);
    }    
}


