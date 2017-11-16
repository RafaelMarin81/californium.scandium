package odins.ezequiel.dtlsproxy;

import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.ScandiumLogger;
import org.eclipse.californium.scandium.dtls.DTLSSession;
//import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.pskstore.InMemoryPskStore;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 * Created by ezequiel on 25/01/16.
 * Modified by Rafa on 1/09/17.
 */
public class DTLSSocket implements Socket {

    static {
        ScandiumLogger.initialize();
        ScandiumLogger.setLevel(Level.FINEST);
    }

    private static final String TRUST_STORE_PASSWORD = "rootPass";
    private static final String KEY_STORE_PASSWORD = "endPass";
    private static final String KEY_STORE_LOCATION = "certs/keyStore.jks";
    private static final String TRUST_STORE_LOCATION = "certs/trustStore.jks";

    private DTLSConnector dtlsConnector;
    private final Set<SocketListener> listeners = new HashSet<SocketListener>();

    private static final Logger LOG = Logger.getLogger(DTLSProxy.class.getName());

    private InetAddress lastAddress;
    private int lastPort;

    public DTLSSocket(int portDtls) {
        createDTLSSocket(portDtls, "secretPSK");
    }
    	
    public DTLSSocket(int portDtls, String PEMK_key) {
        createDTLSSocket(portDtls, PEMK_key);
    }

    public DTLSSocket(int portDtls, byte[] PEMK_key_ByteArray) {
        createDTLSSocket(portDtls, PEMK_key_ByteArray);
    }
    
    public void createDTLSSocket(int portDtls, String DTLS_key_String) {
    	createDTLSSocket(portDtls, DTLS_key_String.getBytes());
    }

    public void createDTLSSocket(int portDtls, byte[] DTLS_key_ByteArray) {
        InMemoryPskStore pskStore = new InMemoryPskStore();
        // put in the PSK store the default identity/psk for tinydtls tests
        pskStore.setKey("Client_identity", DTLS_key_ByteArray);  //"secretPSK".getBytes());
        InputStream in = null;
        try {
            // load the key store
            KeyStore keyStore = KeyStore.getInstance("JKS");
            in = new FileInputStream(KEY_STORE_LOCATION);
            keyStore.load(in, KEY_STORE_PASSWORD.toCharArray());

            // load the trust store
            KeyStore trustStore = KeyStore.getInstance("JKS");
            InputStream inTrust = new FileInputStream(TRUST_STORE_LOCATION);
            trustStore.load(inTrust, TRUST_STORE_PASSWORD.toCharArray());

            // You can load multiple certificates if needed
            Certificate[] trustedCertificates = new Certificate[1];
            trustedCertificates[0] = trustStore.getCertificate("root");

//            DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(new InetSocketAddress(portDtls));
//            builder.setPskStore(pskStore);
//            builder.setIdentity((PrivateKey)keyStore.getKey("server", KEY_STORE_PASSWORD.toCharArray()),
//                    keyStore.getCertificateChain("server"), true);
//            builder.setTrustStore(trustedCertificates);
            
            dtlsConnector = new DTLSConnector(new InetSocketAddress(portDtls), null);
            dtlsConnector.getConfig().setPskStore(new StaticPskStore("Client_identity", DTLS_key_ByteArray)); //"secretPSK".getBytes()));
            dtlsConnector.setRawDataReceiver(new RawDataChannelImpl(dtlsConnector));
            
//            DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(new InetSocketAddress(portDtls));
//            builder.setPskStore(pskStore);
//            builder.setIdentity((PrivateKey)keyStore.getKey("server", KEY_STORE_PASSWORD.toCharArray()),
//                    keyStore.getCertificateChain("server"), true);
//            builder.setTrustStore(trustedCertificates);
//            dtlsConnector = new DTLSConnector(builder.build(), null);
//            dtlsConnector.setRawDataReceiver(new RawDataChannelImpl(dtlsConnector));

        } catch (GeneralSecurityException | IOException e) {
            LOG.log(Level.SEVERE, "Could not load the keystore", e);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    LOG.log(Level.SEVERE, "Cannot close key store file", e);
                }
            }
        }
    }

    @Override
    public void send(byte[] data, int len) {
        if (lastAddress == null) {
            lastAddress = dtlsConnector.getAddress().getAddress();
            lastPort = dtlsConnector.getAddress().getPort();
        }
        byte[] subdata = data;
        if (len < data.length)
            subdata = Arrays.copyOfRange(subdata,0,len);
        LOG.log(Level.INFO, "Sending "+(subdata.length)+" bytes to: " + lastAddress.toString());
        //public DTLSSession getSessionByAddress(InetSocketAddress address);
        dtlsConnector.send(new RawData(subdata, lastAddress, lastPort));
    }

    @Override
    public void addSocketListener(SocketListener sl) {
        listeners.add(sl);
    }

    public void setInitialRemote(String remoteAddressDtls, int remotePortDtls) {
        try {
            lastAddress = InetAddress.getByName(remoteAddressDtls);
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        lastPort = remotePortDtls;
    }

    private class RawDataChannelImpl implements RawDataChannel {

        private Connector connecter;

        public RawDataChannelImpl(Connector con) {
            this.connecter = con;
        }

        @Override
        public void receiveData(final RawData raw) {
            for (SocketListener sl : listeners) {
                sl.onData(raw.bytes, raw.bytes.length, raw.getInetSocketAddress());
            }
            LOG.log(Level.INFO, "Received request: {0}", new String(raw.getBytes()));
        }
    }

    public void accept() {
        try {
            dtlsConnector.start();
        } catch (IOException e) {
            throw new IllegalStateException("Unexpected error starting the DTLS UDP server",e);
        }
    }

    @Override
	public void close() {
		if (this.dtlsConnector != null) dtlsConnector.stop();
		//if (this.isClosed == false) this.close();
		//this.isClosed = true;
	}
    
    
    public void changeAddressing(InetSocketAddress forwardingAddress) {
        lastAddress = forwardingAddress.getAddress();
        lastPort = forwardingAddress.getPort();
    }
}
