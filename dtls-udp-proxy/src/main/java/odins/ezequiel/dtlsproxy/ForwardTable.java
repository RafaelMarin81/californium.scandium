package odins.ezequiel.dtlsproxy;

import java.net.InetSocketAddress;

/**
 * Created by ezequiel on 27/01/16.
 */
public interface ForwardTable {

    void setDefaultForwardingAddress(InetSocketAddress def);

    InetSocketAddress outgoingPacket(InetSocketAddress address, byte[] data);
    void incomingPacket(InetSocketAddress address, byte[] data);
}
