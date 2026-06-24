package Server.Log;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses raw syslog-formatted log lines and extracts security-relevant events.
 * <p>
 * This parser handles the standard syslog format (RFC 3164):
 * <pre>
 *   MMM DD HH:MM:SS hostname service[pid]: message
 * </pre>
 * When a line matches a known security pattern (e.g. a failed password attempt),
 * it is converted into a {@link LogSecurity} object containing the validated
 * and structured data extracted from the log entry.
 * </p>
 *
 * <p>
 * Lines that do not match the expected format, or that contain an invalid IP
 * address, are silently ignored (returning {@code null}).
 * </p>
 *
 * @see LogSecurity
 * @see IPAdress
 */
public class LogParser {

    /**
     * Base pattern matching the standard syslog line structure.
     * <p>Captures the following groups:</p>
     * <ol>
     *   <li>Timestamp  — {@code MMM DD HH:MM:SS} (e.g. {@code Jan  5 10:23:45})</li>
     *   <li>Hostname   — non-whitespace token (e.g. {@code webserver01})</li>
     *   <li>Service    — process name and optional PID (e.g. {@code sshd[4521]})</li>
     *   <li>Message    — the rest of the line after the colon separator</li>
     * </ol>
     * Compiled once as a static field to avoid recompiling on every call.
     */
    private static final Pattern BASE_PATTERN = Pattern.compile(
            "^([A-Z][a-z]{2}\\s+\\d+\\s\\d{2}:\\d{2}:\\d{2})" // group 1 : timestamp
            + "\\s+(\\S+)"                                       // group 2 : hostname
            + "\\s+(.*?):\\s+(.*)$"                              // group 3 : service | group 4 : message
    );

    /**
     * Pattern for detecting a failed password attempt inside the message field.
     * <p>
     * Real sshd emits two variants:
     * <ul>
     *   <li>{@code Failed password for root from 1.2.3.4 port 22}  — valid username</li>
     *   <li>{@code Failed password for invalid user bob from 1.2.3.4 port 22}  — invalid username</li>
     * </ul>
     * The original regex {@code .*user (\S+) from (\S+).*} silently dropped all
     * attempts against valid usernames (no "user" keyword in that form).
     * This pattern handles both variants with an optional "invalid user" prefix.
     * </p>
     * Captures:
     * <ol>
     *   <li>Username  — the user that failed to authenticate</li>
     *   <li>IP source — the remote address the attempt came from</li>
     * </ol>
     */
    private static final Pattern FAILED_PWD_PATTERN = Pattern.compile(
            ".*[Ff]ailed password for (?:invalid user )?(\\S+) from (\\S+).*"
    );

    /**
     * Constructs a new {@code LogParser}.
     * No configuration is required; all patterns are defined as static constants.
     */
    public LogParser() {
    }

    /**
     * Parses a single raw syslog line and returns a {@link LogSecurity} object
     * if the line represents a recognized security event with a valid IP address.
     *
     * <p>The parsing pipeline is:</p>
     * <ol>
     *   <li>Match the full line against {@link #BASE_PATTERN} to extract
     *       timestamp, hostname, service, and message.</li>
     *   <li>Match the message against {@link #FAILED_PWD_PATTERN} to extract
     *       the username and source IP address.</li>
     *   <li>Validate the extracted IP address using {@link IPAdress}.</li>
     *   <li>If all steps succeed, return a populated {@link LogSecurity}.</li>
     * </ol>
     *
     * @param line the raw syslog line to parse (must not be {@code null})
     * @return a {@link LogSecurity} instance if the line is a recognized and
     *         valid security event, or {@code null} if the line does not match
     *         or contains an invalid IP address
     */
    public LogSecurity parse(String line) {

        // --- Step 1: match the overall syslog structure ---
        Matcher baseMatch = BASE_PATTERN.matcher(line);
        if (!baseMatch.matches()) {
            // Line does not follow the expected syslog format — skip it
            return null;
        }

        String date    = baseMatch.group(1); // e.g. "Jan 15 10:23:45"
        String server  = baseMatch.group(2); // e.g. "webserver01"
        String service = baseMatch.group(3); // e.g. "sshd[4521]"
        String message = baseMatch.group(4); // e.g. "Failed password for root from 192.168.1.5 port 22"

        // --- Step 2: check whether the message is a failed-password event ---
        Matcher failMatch = FAILED_PWD_PATTERN.matcher(message);
        if (!failMatch.matches()) {
            // Message is not a failed authentication attempt — not a security event
            return null;
        }

        String user  = failMatch.group(1); // e.g. "root"
        String rawIp = failMatch.group(2); // e.g. "192.168.1.5" (not yet validated)

        // --- Step 3: validate the extracted IP address ---
        try {
            IPAdress validatedIp = new IPAdress(rawIp);
            // All checks passed — return the structured security event
            return new LogSecurity(date, server, service, user, validatedIp);
        } catch (IllegalArgumentException e) {
            // The IP string extracted from the log is malformed — discard the line
            System.err.println("Line ignored (invalid IP address): " + rawIp);
            return null;
        }
    }
}