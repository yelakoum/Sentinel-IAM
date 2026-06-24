package Server.Log;

/**
 * Represents a validated security event extracted from a syslog line.
 * <p>
 * A {@code LogSecurity} instance is created by {@link LogParser} when a log
 * line matches a known security pattern (e.g. a failed authentication attempt)
 * and contains a syntactically valid IP address.
 * </p>
 *
 * <p>
 * All fields are immutable after construction — this class is a read-only
 * data container (value object / DTO).
 * </p>
 *
 * @see LogParser
 * @see IPAdress
 */
public class LogSecurity {

    /** Timestamp of the event as parsed from the syslog line (e.g. {@code "Jan 15 10:23:45"}). */
    private String date;

    /** Hostname or identifier of the server that emitted the log line. */
    private String server;

    /** Name of the service or process that reported the event (e.g. {@code "sshd[4521]"}). */
    private String service;

    /** Username involved in the security event (e.g. the user that failed to authenticate). */
    private String user;

    /** Validated source IP address associated with the event. */
    private IPAdress ip;

    /**
     * Constructs a new {@code LogSecurity} event with all required fields.
     *
     * @param date    the timestamp string extracted from the log line
     * @param server  the hostname of the server that produced the log
     * @param service the service or process name that reported the event
     * @param user    the username involved in the event
     * @param ip      the validated {@link IPAdress} of the remote host
     */
    public LogSecurity(String date, String server, String service, String user, IPAdress ip) {
        this.date    = date;
        this.server  = server;
        this.service = service;
        this.user    = user;
        this.ip      = ip;
    }

    /**
     * Returns the timestamp of the security event.
     *
     * @return the date/time string (e.g. {@code "Jan 15 10:23:45"})
     */
    public String getDate() { return date; }

    /**
     * Returns the hostname of the server that emitted the log.
     *
     * @return the server hostname or identifier
     */
    public String getServer() { return server; }

    /**
     * Returns the name of the service or process that reported the event.
     *
     * @return the service name (e.g. {@code "sshd[4521]"})
     */
    public String getService() { return service; }

    /**
     * Returns the username involved in the security event.
     *
     * @return the username (e.g. {@code "root"})
     */
    public String getUser() { return user; }

    /**
     * Returns the validated source IP address associated with the event.
     *
     * @return the {@link IPAdress} instance
     */
    public IPAdress getIp() { return ip; }

    /**
     * Returns a human-readable summary of this security event.
     * <p>Format: {@code [timestamp] ALERT: User '<username>' failed login from IP <address>}</p>
     *
     * @return a formatted alert string describing the event
     */
    @Override
    public String toString() {
        return "[" + date + "] ALERT: User '" + user
                + "' failed login from IP " + ip.getAdresse();
    }

    /**
     * Compares this security event to another object for equality.
     * Two {@code LogSecurity} instances are equal if all their fields are equal.
     *
     * @param obj the object to compare with
     * @return {@code true} if both instances represent the same event
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof LogSecurity)) return false;
        LogSecurity other = (LogSecurity) obj;
        return date.equals(other.date)
                && server.equals(other.server)
                && service.equals(other.service)
                && user.equals(other.user)
                && ip.equals(other.ip);
    }

    /**
     * Returns a hash code consistent with {@link #equals(Object)}.
     *
     * @return combined hash code of all fields
     */
    @Override
    public int hashCode() {
        int result = date.hashCode();
        result = 31 * result + server.hashCode();
        result = 31 * result + service.hashCode();
        result = 31 * result + user.hashCode();
        result = 31 * result + ip.hashCode();
        return result;
    }
}