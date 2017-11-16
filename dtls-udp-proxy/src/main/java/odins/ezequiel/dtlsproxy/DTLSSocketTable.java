package odins.ezequiel.dtlsproxy;

import java.util.HashMap;

/**
 * Created by Rafa on 10/2017.
 */
public class DTLSSocketTable {
    //private InetSocketAddress defaultFA;
    //final private HashMap<Integer, DTLSSocket> dtlsSocketTable = new HashMap<Integer, DTLSSocket>();
    //final private HashMap<Integer, UDPSocket> udpSocketTable = new HashMap<Integer, UDPSocket>();

    public DTLSSocketTable() {

    }
    
    public void addSocketTable() {
    	
    }
    
    public void removeSocketTable() {
    	
    }
/*
    @Override
    public InetSocketAddress outgoingPacket(InetSocketAddress address, byte[] data) {
        InetSocketAddress result = null;
        int tokenlen = (data[0]&0x0F);
        int mid = (data[3]&0xFF) | ((data[2]&0xFF) << 8);
        long token = -1;
        for (int i = 0; i < tokenlen; i++) {
            token = (token << 8);
            token = (token) | (data[4+i]&0xFF);
        }
        if (tokenlen > 0) {
            result = coapTokenObserveForward.get(token);
        }
        System.out.println(result);
        if (result == null) {
            result = coapMidForward.get(mid);
        }
        System.out.println(result);
        if (result == null) {
            result = defaultFA;
        }
        return result;
    }

    @Override
    public void incomingPacket(InetSocketAddress address, byte[] data) {
        int tokenlen = (data[0]&0x0F);
        int mid = (data[3]&0xFF) | ((data[2]&0xFF) << 8);
        long token = -1;
        for (int i = 0; i < tokenlen; i++) {
            token = (token << 8);
            token = (token) | (data[4+i]&0xFF);
        }
        if (tokenlen > 0) {
            coapTokenObserveForward.put(token, address);
        }
        coapMidForward.put(mid, address);
    }*/
}
