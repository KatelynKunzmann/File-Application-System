import java.io.File;
import java.net.Socket;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Scanner;
import java.security.*;


public abstract class Client {

    /* protected keyword is like private but subclasses have access
     * Socket and input/output streams
     */
    protected Socket sock;
    protected ObjectOutputStream output;
    protected ObjectInputStream input;

    protected byte[] Kab;

    protected RSAPublicKey gsPubKey;

    public boolean connect(final String server, final int port, String username) {
        System.out.println("attempting to connect");

        try {
          sock = new Socket(server, port);  
          output = new ObjectOutputStream(sock.getOutputStream());
          input = new ObjectInputStream(sock.getInputStream());


          // Check to see if the server's public key is cached or not, if not get the key sent by server
            // display it and ask user to verify it out-of-bound. If it is cached don't display, instead compare it
            // to see if group server sent the same public key as the one that is cached.
            // If it is, continue with connection else disconnect and display message saying that
            // the group server could not be verified.
          CryptoSec cs = new CryptoSec();
          Envelope pubKeyMsg = (Envelope)input.readObject();
          gsPubKey = (RSAPublicKey) pubKeyMsg.getObjContents().get(0);
          File serverKeys = new File(username + "_known_servers" + File.separator + pubKeyMsg.getMessage() +".public");

          if (serverKeys.exists()) {
              // Compare key sent by server to the cached one
              RSAPublicKey cachedGSPubKey = cs.readRSAPublicKey(username + "_known_servers" + File.separator + pubKeyMsg.getMessage());
              if(cs.byteArrToHexStr(gsPubKey.getEncoded()).equals(cs.byteArrToHexStr(cachedGSPubKey.getEncoded()))) {
                  System.out.println("The cached public key for this server matched the public key sent by " + server +
                          " at port " + port + ". Connecting...");
              } else {
                  disconnect();
                  System.out.println("Cached public key for server did not match the public key " + server + " at port "
                          + port + " provided. Disconnected. Type 'help' to see options.");
                  return false;
              }
          } else {
              System.out.println("No prior connection to this server found:");
              System.out.println("This group server's RSA public key in hex is:");
              System.out.println(cs.byteArrToHexStr(gsPubKey.getEncoded()));
              System.out.println("Verify with an admin that this matches the group server public key.");
              System.out.println("Enter 'y' to verify that the public key is valid and to continue and connect to the" +
                      " group server or 'n' to end the session:");
              Scanner in = new Scanner(System.in);
              boolean validInput = false;
              while(!validInput) {
                  String userInput = in.nextLine();
                  if (userInput.equalsIgnoreCase("y")) {
                      // Create new directory if it doesn't exist TODO <-- dead code next few lines?
                      File knownServerDir = new File(username + "_known_servers");
                      if(!knownServerDir.exists() && !knownServerDir.mkdir()) {
                              System.out.println("Error creating " + knownServerDir);
                      }
                      String pubKeyFilePath = username + "_known_servers" + File.separator + pubKeyMsg.getMessage();
                      if (cs.writePubKey(pubKeyFilePath, gsPubKey)) {
                          System.out.println("Group Server's public key cached in " + pubKeyFilePath);
                      }
                      validInput = true;
                  } else if (userInput.equalsIgnoreCase("n")) {
                      disconnect();
                      System.out.println("Disconnected. Type 'help' to see options.");
                      return false;
                  } else {
                      System.out.println("Invalid input. Enter 'y' to verify that the public key is valid and connect" +
                              " to the group server or 'n' to end the session:");
                  }
              }
          }
            /** To establish a secure connection, a handshake is done.
            * Steps: After user clicks/types "connect to group/file server"
            * 1) ECDH keypair is generated
            * 2) Sign ECDH public key with RSA private key
            * 3) Send to server you want to connect with
            * 4) Repeat steps 1-3 for server to send to client
            * 5) Key Agreement - generation of Kab
            */

            // 1) ECDH keypair is generated
          KeyPair ecKeyPair = cs.genECDHKeyPair();
          //          System.out.println(ecKeyPair.getPublic().toString());
          //          System.out.println(ecKeyPair.getPrivate().toString());
          RSAPrivateKey userRSAprivatekey = cs.readRSAPrivateKey(username);
          if (userRSAprivatekey == null) {
              System.out.println("Could not find " + username + "'s RSA private key.");
          }
          RSAPublicKey userRSApublickey = cs.readRSAPublicKey(username);
          if (userRSApublickey == null) {
              System.out.println("Could not find " + username + "'s RSA public key.");
          }
          // 2) Sign ECDH public key with RSA private key
          byte[] UserECDHpubKeySigned = cs.rsaSign(userRSAprivatekey, ecKeyPair.getPublic().getEncoded());
            // 3) Send to server you want to connect with
          Envelope connectRequest = new Envelope("SignatureForHandshake");
          connectRequest.addObject(username);
          connectRequest.addObject(userRSApublickey); // So the server can verify the signature 
          connectRequest.addObject(ecKeyPair.getPublic());
          connectRequest.addObject(UserECDHpubKeySigned);
          output.writeObject(connectRequest);

          /**
           * Server handshake part
           */
          Envelope serverHandshake = (Envelope)input.readObject();
          if(serverHandshake.getMessage().equals("FAIL")) {
            System.err.println("ERROR: Handshake Failed on server end; \nEither content is null or signature cannot be verified.");
            return false;
          } else if(serverHandshake.getMessage().equals("SignatureForHandshake")) {

                // Fetch content
                PublicKey serverECDHPubKey = (PublicKey) serverHandshake.getObjContents().get(0);
                byte [] serverECDHKeySig = (byte []) serverHandshake.getObjContents().get(1);
                if (serverECDHKeySig == null) {
                    System.err.println("ERROR: Signature from server is null");
                    return false;
                }
                // Must verify server signature
                Signature verifySig = Signature.getInstance("SHA256withRSA", "BC");
                verifySig.initVerify(gsPubKey);
                verifySig.update(serverECDHPubKey.getEncoded());
                if(!verifySig.verify(serverECDHKeySig)) {
                    System.err.println("ERROR: Signature from server cannot be verified");
                    return false;
                }

                // Generate Kab, shared secret between user and server
                Kab = cs.generateSharedSecret(ecKeyPair.getPrivate(), serverECDHPubKey);
//                System.out.println("client side shared secret: " + cs.byteArrToHexStr(Kab));
              // Send over HMAC(Kab + name) to prove to server, the user was able to arrive at shared secret
              output.reset();
              byte[] KabHMAC = cs.genKabHMAC(Kab, username);
              if (KabHMAC != null) {
//                  serverHandshake = new Envelope("KabConfirmation");
//                  serverHandshake.addObject(KabHMAC);
                  output.writeObject(KabHMAC);

                  // Confirm that the server arrived at the same Kab
                  byte[] serverKabHMAC = (byte[]) input.readObject();
                  if (serverKabHMAC != null) {
                      // not the best approach to hardcode 'gs', gclient should probably override this method
                      // like fclient does
                      byte[] genGSKabHMAC = cs.genKabHMAC(Kab, "gs");
                      if (genGSKabHMAC != null && Arrays.equals(serverKabHMAC, genGSKabHMAC)) {
                          System.out.println("Confirmed server arrived at the same shared secret Kab.");
                      } else {
                          System.out.println("Could not confirm whether server arrived at same shared secret Kab.");
                          return false;
                      }

                  } else {
                      System.out.println("Failed to receive confirmation whether server arrived at same shared secret Kab.");
                      return false;
                  }
              } else {
                  System.out.println("Error generating shared secret Kab.");
                  return false;
              }

                // DEBUG: System.err.println("Shared secret: ", printHexBinary(Kab));
          } else {
            // Message received was neither "SignatureForHandshake" nor "FAIL"
            System.err.println("ERROR: Message received was neither SignatureForHandshake nor FAIL");
            return false;
          }

          System.out.println("Connected to " + server + " on port " + port);
          return true;
        }
        catch(Exception e){
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }


    public boolean isConnected() {
        if (sock == null || !sock.isConnected()) {
            return false;
        } else {
            return true;
        }
    }

    public void disconnect() {
        if (isConnected()) {
            try {
                Envelope message = new Envelope("DISCONNECT");
                output.writeObject(message);
                sock.close();
                sock = null;
                Kab = null;
            } catch(Exception e) {
                System.err.println("Error: " + e.getMessage());
                e.printStackTrace(System.err);
            }
        }
    }
}
