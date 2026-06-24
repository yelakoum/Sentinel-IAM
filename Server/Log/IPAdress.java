package Server.Log;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Represents a validated IP address (IPv4 or IPv6).
 * <p>
 * This class validates the format of an IP address string upon construction
 * and provides utility methods to inspect basic properties of the address,
 * such as whether it is IPv6 and whether it belongs to a private/reserved range.
 * </p>
 *
 * <p>
 * Note: This class only validates the <b>format</b> of the address.
 * It does not perform any network-level checks (reachability, DNS resolution,
 * geolocation, etc.). For connection monitoring / intrusion detection,
 * this class should be used as a first validation layer, combined with
 * additional logic (rate limiting, blacklists, geo-IP, etc.).
 * </p>
 */
public class IPAdress {

    /** The validated IP address string (IPv4 or IPv6). */
    private String adresse;

    /** Flag indicating whether the address is IPv6 (true) or IPv4 (false). */
    private boolean isV6;

    /**
     * Regex pattern for validating IPv4 addresses.
     * <p>
     * Matches four octets (0-255) separated by dots, anchored to the whole string.
     * </p>
     */
    private static final String IPV4_PATTERN =
            "^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
            + "(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$";

    /**
     * Compiled pattern for IPv4 validation.
     * Created once as a static field for performance (avoids recompiling
     * the regex on every check).
     */
    private static final Pattern ipv4 = Pattern.compile(IPV4_PATTERN);

    /**
     * Regex pattern for validating IPv6 addresses.
     * <p>
     * Covers full notation, compressed notation ("::"), link-local addresses
     * with zone index ("fe80::...%eth0"), and IPv4-mapped/embedded IPv6 addresses.
     * </p>
     */
    private static final String IPV6_PATTERN =
            "^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$";

    /**
     * Compiled pattern for IPv6 validation.
     * Created once as a static field for performance (avoids recompiling
     * the regex on every check).
     */
    private static final Pattern ipv6 = Pattern.compile(IPV6_PATTERN);

    /**
     * Constructs an {@code IPAdress} after validating its format.
     *
     * @param adresse the IP address string to validate (IPv4 or IPv6)
     * @throws IllegalArgumentException if the given string is not a valid
     *                                   IPv4 or IPv6 address
     */
    public IPAdress(String adresse) throws IllegalArgumentException {
        Matcher m_ipv4 = ipv4.matcher(adresse);
        Matcher m_ipv6 = ipv6.matcher(adresse);

        if (m_ipv4.matches()) {
            this.adresse = adresse;
            this.isV6 = false;
        } else if (m_ipv6.matches()) {
            this.adresse = adresse;
            this.isV6 = true;
        } else {
            throw new IllegalArgumentException("Invalid IP Address: " + adresse);
        }
    }

    /**
     * Returns the validated IP address as a string.
     *
     * @return the IP address (IPv4 or IPv6 notation)
     */
    public String getAdresse() {
        return adresse;
    }

    /**
     * Indicates whether this address is an IPv6 address.
     *
     * @return {@code true} if the address is IPv6, {@code false} if it is IPv4
     */
    public boolean isIPv6() {
        return isV6;
    }

    /**
     * Indicates whether this address belongs to a private, loopback,
     * or link-local range.
     * <p>
     * For IPv4, the following ranges are considered private/reserved:
     * <ul>
     *   <li>10.0.0.0/8</li>
     *   <li>172.16.0.0/12</li>
     *   <li>192.168.0.0/16</li>
     *   <li>127.0.0.0/8 (loopback)</li>
     * </ul>
     * For IPv6, addresses starting with {@code fe80} (link-local),
     * {@code fc} or {@code fd} (unique local addresses), or {@code ::1}
     * (loopback) are considered private.
     * </p>
     *
     * @return {@code true} if the address is private/reserved, {@code false} otherwise
     */
    public boolean isPrivate() {
        if (isV6) {
            String lower = adresse.toLowerCase();
            return lower.startsWith("fe80")
                    || lower.startsWith("fc")
                    || lower.startsWith("fd")
                    || lower.equals("::1");
        }

        if (adresse.equals("127.0.0.1") || adresse.startsWith("127.")) {
            return true;
        }
        if (adresse.startsWith("10.")) {
            return true;
        }
        if (adresse.startsWith("192.168.")) {
            return true;
        }
        // 172.16.0.0 - 172.31.255.255
        if (adresse.matches("^172\\.(1[6-9]|2[0-9]|3[01])\\..*")) {
            return true;
        }
        return false;
    }

    /**
     * Indicates whether this address is the IPv4 or IPv6 loopback address.
     *
     * @return {@code true} if the address is a loopback address
     */
    public boolean isLoopback() {
        if (isV6) {
            return adresse.equalsIgnoreCase("::1");
        }
        return adresse.startsWith("127.");
    }

    /**
     * Returns a string representation of this IP address,
     * including its type (IPv4/IPv6).
     *
     * @return a human-readable description of the address
     */
    @Override
    public String toString() {
        return adresse + " (" + (isV6 ? "IPv6" : "IPv4") + ")";
    }

    /**
     * Compares this IP address to another object for equality.
     * Two {@code IPAdress} instances are equal if their string
     * representations are equal.
     *
     * @param obj the object to compare with
     * @return {@code true} if both represent the same IP address
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof IPAdress)) return false;
        IPAdress other = (IPAdress) obj;
        return this.adresse.equals(other.adresse);
    }

    /**
     * Returns a hash code consistent with {@link #equals(Object)}.
     *
     * @return the hash code of the underlying address string
     */
    @Override
    public int hashCode() {
        return adresse.hashCode();
    }
}