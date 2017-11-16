package odins.ezequiel.dtlsproxy;

import java.net.InetSocketAddress;

/**
 * Created by ezequiel on 25/01/16.
 */
public interface SocketListener {
    void onData(byte[] data, int len, InetSocketAddress address);
}
