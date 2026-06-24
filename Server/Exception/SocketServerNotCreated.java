package Server.Exception;

/**
 * Exception thrown when an operation is attempted on a {@code Server}
 * whose underlying socket has not yet been created (i.e. {@code createServer()}
 * was not called or failed).
 */
public class SocketServerNotCreated extends Exception {

    /**
     * Constructs a new exception with no detail message.
     */
    public SocketServerNotCreated() {
        super();
    }

    /**
     * Constructs a new exception with the specified detail message.
     *
     * @param msg the detail message
     */
    public SocketServerNotCreated(String msg) {
        super(msg);
    }
}