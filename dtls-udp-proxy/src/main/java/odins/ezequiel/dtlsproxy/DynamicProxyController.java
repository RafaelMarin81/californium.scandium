package odins.ezequiel.dtlsproxy;

import java.io.IOException;
import java.net.*;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;


/**
 * Created by Rafa on 10/2017.
 */
public class DynamicProxyController implements Socket {
	

	private Thread t;
    private DatagramSocket serverSocket;
    final private Set<SocketListener> listeners = new HashSet<SocketListener>();

    public DynamicProxyController(int port) throws IOException {
        serverSocket = new DatagramSocket(port);
    }

    @Override
    public void send(byte[] data, int len) {
        /*System.out.println("UDP: Sending "+len+" bytes to "+lastAddress+" : "+lastPort);
        DatagramPacket sendPacket = new DatagramPacket(data, (len > data.length ? data.length : len), lastAddress, lastPort);
        try {
            serverSocket.send(sendPacket);
        } catch (IOException e) {
            e.printStackTrace();
        }*/
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
                    DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
                    try {
                        serverSocket.receive(receivePacket);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    String sentence = new String(receivePacket.getData(), 0, receivePacket.getLength());
                    System.out.println("RECEIVED " + receivePacket.getLength() + " bytes: " + sentence);
                                        
                    for (SocketListener sl : listeners) {
                        sl.onData(receiveData, receivePacket.getLength(),
                                new InetSocketAddress(receivePacket.getAddress(), receivePacket.getPort()));
                    }
                }
            }
        });
        t.start();
    }


        
    public void close() {
		if (this.t != null) t.interrupt();
		if (this.serverSocket != null) this.serverSocket.close();        
    }

    
}
