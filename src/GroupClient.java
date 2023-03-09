/* Implements the GroupClient Interface */
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKey;


public class GroupClient extends Client implements GroupClientInterface {

    CryptoSec cs;
    int sequence = 0;
    public GroupClient() {
        cs = new CryptoSec();
    }

    public SignedToken getToken(String username, RSAPublicKey recipientPubKey) {
        try {
            Envelope message = null, response = null;

            //Tell the server to return a token.
            message = new Envelope("GET");
            message.addObject(username); // Add user name string
            message.addObject(recipientPubKey); // Add the intended recipient's public key
            Message encryptedMsg = cs.encryptEnvelope(message, Kab, ++sequence);

            output.writeObject(encryptedMsg);

            //Get the response from the server
            encryptedMsg = (Message) input.readObject();
            response = cs.decryptEnvelopeMessage(encryptedMsg, Kab, ++sequence);

            //Successful response
            if(response.getMessage().equals("OK")) {
                //If there is a token in the Envelope, return it
                
                ArrayList<Object> temp = null;
                temp = response.getObjContents();
                ArrayList<String> groups = (ArrayList<String>) temp.get(1);
                if (groups.size() == temp.size()-2){
                    for(int i = 2; i<temp.size();i++){
                        cs.writeGroupKey(groups.get(i-2), (ArrayList<SecretKey>) temp.get(i));
                    }
                    return cs.decryptMessageToSignedToken((Message) temp.get(0), Kab, sequence) ;
                }
                
                
            }

            return null;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
        }

    }

    public boolean createUser(String username, SignedToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to create a user
            message = new Envelope("CUSER");
            message.addObject(username); //Add username
            message.addObject(token);
            Message encryptedMessage = cs.encryptEnvelope(message, Kab, ++sequence);
            output.writeObject(encryptedMessage);

            response = cs.decryptEnvelopeMessage((Message) input.readObject(), Kab, ++sequence);
            if (response.getMessage().equals("InvalidTokenRecipient")) {
                System.out.println("The intended recipient in token was invalid.");
            } else if (response.getMessage().equals("FAIL-EXPIREDTOKEN")) {
                System.out.println("Failed: Expired Token.");
            }
            // If server indicates success, return true
            return response.getMessage().equals("OK");
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean deleteUser(String username, SignedToken token) {
        try {
            Envelope message = null, response = null;

            //Tell the server to delete a user
            message = new Envelope("DUSER");
            message.addObject(username); //Add username
            message.addObject(token);
            Message encryptedMessage = cs.encryptEnvelope(message, Kab, ++sequence); // encrypt envelope
            output.writeObject(encryptedMessage);

            response = cs.decryptEnvelopeMessage((Message) input.readObject(), Kab, ++sequence);
            if (response.getMessage().equals("InvalidTokenRecipient")) {
                System.out.println("The intended recipient in token was invalid.");
            } else if (response.getMessage().equals("FAIL-EXPIREDTOKEN")) {
                System.out.println("Failed: Expired Token.");
            }
            //If server indicates success, return true
            return response.getMessage().equals("OK");
        } catch(Exception e) {
            
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean createGroup(String groupname, SignedToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to create a group
            message = new Envelope("CGROUP");
            message.addObject(groupname); //Add the group name string
            message.addObject(token);
            Message encryptedMessage = cs.encryptEnvelope(message, Kab, ++sequence); // encrypt envelope
            output.writeObject(encryptedMessage);

            response = cs.decryptEnvelopeMessage((Message) input.readObject(), Kab, ++sequence);

            if (response.getMessage().equals("InvalidTokenRecipient")) {
                System.out.println("The intended recipient in token was invalid.");
            } else if (response.getMessage().equals("FAIL-EXPIREDTOKEN")) {
                System.out.println("Failed: Expired Token.");
            }
            //If server indicates success, return true
            return response.getMessage().equals("OK");
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean deleteGroup(String groupname, SignedToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to delete a group
            message = new Envelope("DGROUP");
            message.addObject(groupname); //Add group name string
            message.addObject(token);
            Message encryptedMessage = cs.encryptEnvelope(message, Kab, ++sequence); // encrypt envelope
            output.writeObject(encryptedMessage);

            response = cs.decryptEnvelopeMessage((Message) input.readObject(), Kab, ++sequence);

            if (response.getMessage().equals("InvalidTokenRecipient")) {
                System.out.println("The intended recipient in token was invalid.");
            } else if (response.getMessage().equals("FAIL-EXPIREDTOKEN")) {
                System.out.println("Failed: Expired Token.");
            }
            //If server indicates success, return true
            return response.getMessage().equals("OK");
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    public List<String> listMembers(String group, SignedToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to return the member list
            message = new Envelope("LMEMBERS");
            message.addObject(group); //Add group name string
            message.addObject(token);
            Message encryptedMessage = cs.encryptEnvelope(message, Kab, ++sequence); // encrypt envelope
            output.writeObject(encryptedMessage);

            response = cs.decryptEnvelopeMessage((Message) input.readObject(), Kab, ++sequence);

            //If server indicates success, return the member list
            if(response.getMessage().equals("OK")) {
                return (List<String>)response.getObjContents().get(0); // This cast creates compiler warnings. Sorry.
            } else if (response.getMessage().equals("InvalidTokenRecipient")) {
                System.out.println("The intended recipient in token was invalid.");
            } else if (response.getMessage().equals("FAIL-EXPIREDTOKEN")) {
                System.out.println("Failed: Expired Token.");
            }

            return null;

        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
        }
    }

    public boolean addUserToGroup(String username, String groupname, SignedToken token) {
        try {
            Envelope message = null, response = null;

            // Tell the server to add a user to the group
            message = new Envelope("AUSERTOGROUP");
            message.addObject(username); //Add user name string
            message.addObject(groupname); //Add group name string
            message.addObject(token);
            Message encryptedMessage = cs.encryptEnvelope(message, Kab, ++sequence); // encrypt envelope
            output.writeObject(encryptedMessage);

            response = cs.decryptEnvelopeMessage((Message) input.readObject(), Kab, ++sequence);

            if (response.getMessage().equals("InvalidTokenRecipient")) {
                System.out.println("The intended recipient in token was invalid.");
            } else if (response.getMessage().equals("FAIL-EXPIREDTOKEN")) {
                System.out.println("Failed: Expired Token.");
            }
            //If server indicates success, return true
            return response.getMessage().equals("OK");
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean deleteUserFromGroup(String username, String groupname, SignedToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to remove a user from the group
            message = new Envelope("RUSERFROMGROUP");
            message.addObject(username); //Add user name string
            message.addObject(groupname); //Add group name string
            message.addObject(token);
            Message encryptedMessage = cs.encryptEnvelope(message, Kab, ++sequence); // encrypt envelope
            output.writeObject(encryptedMessage);

            response = cs.decryptEnvelopeMessage((Message) input.readObject(), Kab, ++sequence);
            if (response.getMessage().equals("InvalidTokenRecipient")) {
                System.out.println("The intended recipient in token was invalid.");
            } else if (response.getMessage().equals("FAIL-EXPIREDTOKEN")) {
                System.out.println("Failed: Expired Token.");
            }
            //If server indicates success, return true
            return response.getMessage().equals("OK");
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

}
