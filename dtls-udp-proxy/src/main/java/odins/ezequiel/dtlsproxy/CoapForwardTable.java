package odins.ezequiel.dtlsproxy;

import java.net.InetSocketAddress;
import java.util.HashMap;

/**
 * Created by ezequiel on 27/01/16.
 * Modified by Rafa on 1/09/17.
 */
public class CoapForwardTable implements ForwardTable {
    private InetSocketAddress defaultFA;
    final private HashMap<Integer, InetSocketAddress> coapMidForward = new HashMap<Integer, InetSocketAddress>();
    final private HashMap<Long, InetSocketAddress> coapTokenObserveForward = new HashMap<Long, InetSocketAddress>();

    public CoapForwardTable() {

    }

    @Override
    public void setDefaultForwardingAddress(InetSocketAddress def) {
        defaultFA = def;
    }

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
    }
}
