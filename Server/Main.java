package Server;

import java.io.BufferedReader;

import java.io.InputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import Server.Exception.SocketServerNotCreated;
import Server.Log.LogParser;
import Server.Log.LogProducer;
import Server.Log.LogSecurity;

/**
 * Entry point of the log monitoring server application.
 * <p>
 * This class starts a {@link Server} on a fixed port, reads incoming data
 * line by line, and parses each line for security events using {@link LogParser}.
 * Recognized security events (e.g. failed login attempts) are collected into
 * an in-memory list of {@link LogSecurity} objects for further processing.
 * </p>
 */
public class Main {

    /**
     * Application entry point.
     * <p>
     * Workflow:
     * <ol>
     *   <li>Create and bind a {@link Server} on port 8080.</li>
     *   <li>Wrap the raw {@link InputStream} in a {@link BufferedReader}
     *       to read text line by line.</li>
     *   <li>Parse each line with {@link LogParser#parse(String)}.</li>
     *   <li>Collect valid {@link LogSecurity} events into {@code logDatabase}.</li>
     *   <li>Close streams when the connection ends (no more lines).</li>
     * </ol>
     * </p>
     *
     * @param args command-line arguments (not used)
     * @throws IOException              if an I/O error occurs while reading
     *                                  from the socket stream
     * @throws SocketServerNotCreated   if the server socket could not be
     *                                  created or bound to port 8080
     */
    public static void main(String[] args) throws SocketServerNotCreated {

        LogParser parser = new LogParser();
        LogProducer producer = new LogProducer();

        // In-memory storage for all recognized security events across all connections
        List<LogSecurity> logDatabase = new ArrayList<>();

        // --- Bind the ServerSocket once, then loop to accept new clients indefinitely ---
        // The ServerSocket is created outside the loop so the OS port is bound only once.
        // Each iteration of the loop accepts one client (e.g. a `nc` pipe from surveille.sh),
        // drains its stream, then loops back to wait for the next connection.
        // Without this loop the process exits as soon as the first nc session closes (Bug 2).
        Server myServer = new Server(8080);

        System.out.println("[*] Server started on port 8080. Waiting for connections...");

        // BUG FIX: bind the ServerSocket ONCE here, outside the loop.
        // The old code called createServer() (which internally called new ServerSocket(...))
        // on every iteration, causing "Address already in use" on the second connection.
        try {
            myServer.bindPort();
        } catch (IOException e) {
            System.err.println("[FATAL] Cannot bind port 8080: " + e.getMessage());
            return;
        }

        while (true) {
            try {
                // --- Step 1: block until a new client connects ---
                myServer.acceptClient();
                System.out.println("[+] Client connected.");

                // --- Step 2: set up I/O streams for this connection ---
                // NOTE: This server is read-only (it only receives log lines from nc).
                // No OutputStream is needed; obtaining one unnecessarily wastes a resource.
                InputStream inputStream = myServer.getInputStream();
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));

                // --- Step 3: read and parse lines until the client disconnects ---
                String line = bufferedReader.readLine();
                while (line != null) {
                    LogSecurity log = parser.parse(line);
                    if (log != null) {
                        System.out.println(log.toString());
                        logDatabase.add(log);
                        producer.sendAlert(log);
                    }
                    line = bufferedReader.readLine();
                }

                // --- Step 4: clean up this connection's streams ---
                inputStream.close();
                System.out.println("[-] Client disconnected. Waiting for next connection...");

            } catch (IOException e) {
                System.err.println("[ERROR] I/O error on connection: " + e.getMessage());
                // Continue the loop — a single bad connection must not kill the server
            }
        }
    }
}