package odins.ezequiel.dtlsproxy;

/**
 * Created by ezequiel on 25/01/16.
 */
public interface Socket {
    void send(byte[] data, int len);
    void addSocketListener(SocketListener sl);
	void close();
}
