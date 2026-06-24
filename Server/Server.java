package Server;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;

import Server.Exception.SocketServerNotCreated;

/**
 * A simple TCP server wrapper around {@link ServerSocket} and {@link Socket}.
 * This class listens on a given port, accepts a single client connection,
 * and exposes input/output streams for communication with that client.
 *
 * @author ElAkoum
 */
public class Server {

    /** The port on which the server listens for incoming connections. */
    private final int port;

    /** The accepted client socket, used for reading/writing data. */
    private Socket socket;

    /** The underlying server socket that listens for connections. */
    private ServerSocket serverSocket;

    /**
     * Creates a new server bound to the given port.
     *
     * @param port the port number the server will listen on
     */
    public Server(int port) {
        this.port = port;
        this.serverSocket = null;
        this.socket = null;
    }

    /**
     * Returns the port this server listens on.
     *
     * @return the server's port number
     */
    protected int getPort() {
        return this.port;
    }

    /**
     * Binds a {@link ServerSocket} to the configured port.
     * Must be called once before the first {@link #acceptClient()} call.
     * Calling it again while a ServerSocket is already open has no effect.
     *
     * @throws IOException if the port cannot be bound
     */
    public void bindPort() throws IOException {
        if (this.serverSocket == null || this.serverSocket.isClosed()) {
            this.serverSocket = new ServerSocket(this.getPort());
        }
    }

    /**
     * Blocks until a new client connects, then stores the resulting socket.
     * {@link #bindPort()} must have been called first.
     *
     * @throws IOException if an I/O error occurs while waiting for a connection
     */
    public void acceptClient() throws IOException {
        try {
            this.socket = this.serverSocket.accept();
        } catch (IOException e) {
            throw new IOException("An I/O error occurred while waiting for a connection.", e);
        }
    }

    /**
     * @deprecated Use {@link #bindPort()} once + {@link #acceptClient()} in a loop instead.
     *             Calling this method inside a loop re-creates the ServerSocket on every
     *             iteration, which throws "Address already in use" on the second call.
     * @throws IOException if an I/O error occurs
     */
    @Deprecated
    public void createServer() throws IOException {
        bindPort();
        acceptClient();
    }

    /**
     * Returns the output stream used to send data to the connected client.
     *
     * @return the socket's output stream
     * @throws IOException if an I/O error occurs while retrieving the stream
     * @throws SocketServerNotCreated if the server socket has not been created yet
     */
    public OutputStream getOutputStream() throws IOException, SocketServerNotCreated {
        if (this.socket != null) {
            return this.socket.getOutputStream();
        } else {
            throw new SocketServerNotCreated("The server socket has not been created. Call createServer() first.");
        }
    }

    /**
     * Returns the input stream used to receive data from the connected client.
     *
     * @return the socket's input stream
     * @throws IOException if an I/O error occurs while retrieving the stream
     * @throws SocketServerNotCreated if the server socket has not been created yet
     */
    public InputStream getInputStream() throws IOException, SocketServerNotCreated {
        if (this.socket != null) {
            return this.socket.getInputStream();
        } else {
            throw new SocketServerNotCreated("The server socket has not been created. Call createServer() first.");
        }
    }
}