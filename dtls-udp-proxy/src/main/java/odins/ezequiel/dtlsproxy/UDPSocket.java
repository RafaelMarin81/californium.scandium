package odins.ezequiel.dtlsproxy;

import java.io.IOException;
import java.net.*;
import java.util.HashSet;
import java.util.Set;

/**
 * Created by ezequiel on 25/01/16.
 * Modified by Rafa on 1/09/17.
 */
public class UDPSocket implements Socket {

	private Thread t;
    private DatagramSocket serverSocket;
    private int lastPort;
    private InetAddress lastAddress;
    final private Set<SocketListener> listeners = new HashSet<SocketListener>();

    public UDPSocket(int port) throws IOException {
        serverSocket = new DatagramSocket(port);
    }

    @Override
    public void send(byte[] data, int len) {
        System.out.println("UDP: Sending "+len+" bytes to "+lastAddress+" : "+lastPort);
        DatagramPacket sendPacket = new DatagramPacket(data, (len > data.length ? data.length : len), lastAddress, lastPort);
        try {
            serverSocket.send(sendPacket);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    @Override
    public void addSocketListener(SocketListener sl) {
        listeners.add(sl);
    }

    public void accept() {
        t = new Thread(new Runnable() {
            @Override
            public void run() {
                byte[] receiveData = new byte[1536];
                while(true) {
                	if(serverSocket.isClosed()) {
                		return;
                	} else {             		
                		DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
                		try {                			
                			if(serverSocket.isClosed()) {
                				return;
                			} else {
                				serverSocket.receive(receivePacket);	
                			}                			            		                   	                			
                    		String sentence = new String(receivePacket.getData(), 0, receivePacket.getLength());
                    		System.out.println("RECEIVED " + receivePacket.getLength() + " bytes: " + sentence);
                    		for (SocketListener sl : listeners) {
                    			if(serverSocket.isClosed()) { 
                    				return;
                    			} else {
                    				sl.onData(receiveData, receivePacket.getLength(),
                        					new InetSocketAddress(receivePacket.getAddress(), receivePacket.getPort()));	
                    			}                			
                    		}
                    	} catch (IOException e) {
                    		//e.printStackTrace();
                    	} finally {
                    		
                    	}                  		
                    
                	}
                }
            }
        });
        t.start();
    }

    public void setInitialRemote(String remoteAddressUdp, int remotePortUdp) {
        try {
            lastAddress = InetAddress.getByName(remoteAddressUdp);
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        lastPort = remotePortUdp;
    }

    public void changeAddressing(InetSocketAddress forwardingAddress) {
        System.out.println("Changing address: "+forwardingAddress);
        lastAddress = forwardingAddress.getAddress();
        lastPort = forwardingAddress.getPort();
    }

    @Override
	public void close() {
		if (t != null) t.interrupt();		
    	if (serverSocket != null) serverSocket.close();
	}
    
    
}
