
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;

/**
 * A simple interface to the token data structure that will be
 * returned by a group server.
 * You will need to develop a class that implements this interface so
 * that your code can interface with the tokens created by your group
 * server.
 */
public interface UserToken {
    /**
     * This method should return a string describing the issuer of
     * this token.  This string identifies the group server that
     * created this token.  For instance, if "Alice" requests a token
     * from the group server "Server1", this method will return the
     * string "Server1".
     *
     * @return The issuer of this token
     *
     */
    public String getIssuer();


    /**
     * This method should return a string indicating the name of the
     * subject of the token.  For instance, if "Alice" requests a
     * token from the group server "Server1", this method will return
     * the string "Alice".
     *
     * @return The subject of this token
     *
     */
    public String getSubject();


    /**
     * This method extracts the list of groups that the owner of this
     * token has access to.  If "Alice" is a member of the groups "G1"
     * and "G2" defined at the group server "Server1", this method
     * will return ["G1", "G2"].
     *
     * @return The list of group memberships encoded in this token
     *
     */
    public List<String> getGroups();

    /**
     * This method returns an Instant timestamp dating to when the
     * token was created to be used to check for expiry. Instant
     * timestamp is based on second since the Unix Epoch and is
     * not tied to local timezones.
     *
     * @return An Instant timestamp dating to initial token creation
     */
    public Instant getTimestamp();


    /**
     * This method returns a RSAPublicKey containing the token's intended
     * recipient's public key. For example if the token was created to be used
     * at the group server, this method will return the group server's
     * public key.*
     * @return A RSAPublicKey containing the intended recipient public key in hex
     * */
    public RSAPublicKey getRecipientPubKey();

}   //-- end interface UserToken
