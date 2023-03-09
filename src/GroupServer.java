/* Group server. Server loads the users from UserList.bin.
 * If user list does not exists, it creates a new list and makes the user the server administrator.
 * On exit, the server saves the user list to file.
 */

/*
 * TODO: This file will need to be modified to save state related to
 *       groups that are created in the system
 */

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.util.Scanner;

public class GroupServer extends Server {

    public UserList userList;
    public GroupList groupList;

    public GroupServer(int _port) {
        super(_port, "alpha");
    }

    public void start() {
        // Overwrote server.start() because if no user file exists, initial admin account needs to be created

        String userFile = "UserList.bin";
        String groupFile = "GroupList.bin";
        Scanner console = new Scanner(System.in);
        ObjectInputStream userStream;
        ObjectInputStream groupStream;

        //This runs a thread that saves the lists on program exit
        Runtime runtime = Runtime.getRuntime();
        runtime.addShutdownHook(new ShutDownListener(this));

        //Open user file to get user list
        try {
            FileInputStream fis = new FileInputStream(userFile);
            userStream = new ObjectInputStream(fis);
            userList = (UserList)userStream.readObject();

//            System.out.println(userList.getUserGroups("admin").get(0));

        } catch(FileNotFoundException e) {
            System.out.println("UserList File Does Not Exist. Creating UserList...");
            System.out.println("No users currently exist. Your account will be the administrator.");
            System.out.print("Enter your username: ");
            String username = console.next();

            //Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
            userList = new UserList();
            userList.addUser(username);
            userList.addGroup(username, "ADMIN");
            userList.addOwnership(username, "ADMIN");
            System.out.println("Generating and storing RSA key pair for " + username + "...");

            // Generate RSA keypair for the user and another for the group server
            // TODO remove rsa keygen for user from here, it should happen in client terminal app like normal
            CryptoSec cs = new CryptoSec();
//            cs.writeKeyPair(username, cs.genRSAKeyPair());
//            System.out.println("An RSA Key Pair has been generated for " + username +
//                    " and stored in files '" + username +
//                    ".public' and '" + username + ".private' in the current directory.");
//            System.out.println();
            System.out.println("RSA Keypair will be created for " + username + " when they run their client app" +
                    " for the first time.");

            KeyPair gsKeyPair =  cs.genRSAKeyPair();
            cs.writeKeyPair("gs", gsKeyPair);
            System.out.println("An RSA Key Pair has been generated for the group server and stored in files " +
                    "'gs.public' and 'gs.private' in the current directory.");

            // Write a hex version of the group server's public key to a new file, meant to be used for verification
            // purposes
            String pubHexString = cs.byteArrToHexStr(gsKeyPair.getPublic().getEncoded());
            if (cs.writeStrToFile("gs_pub_key_hex", pubHexString)) {
                System.out.println("A hex version of the Group Server's public key has been written to" +
                        " gs_pub_key_hex.txt in the current directory.");
                System.out.println("This is meant to be given to trusted new users out-of-band as needed so they can" +
                        " verify they are connecting to the right group server.");
            } else {
                System.out.println("There was an error writing hex version of the group servers public key to file.");
            }
            System.out.println();

//            System.out.println(cs.readRSAPublicKey(username).toString());
//            System.out.println(cs.readRSAPrivateKey(username).toString());

        } catch(IOException | ClassNotFoundException e) {
            System.out.println("Error reading from UserList file");
            System.exit(-1);
        }

        // Open group file to get group list
        try {
            FileInputStream gfis = new FileInputStream(groupFile);
            groupStream = new ObjectInputStream(gfis);
            groupList = (GroupList) groupStream.readObject();
        } catch(FileNotFoundException e) {
            System.out.println("Group File Does Not Exist. Creating GroupList...");
            groupList = new GroupList();
            System.out.println("No Group currently exists.");
            // I don't think you inititalize it here by creating a group unlike UserList which has the ADMIN case
                    
        } catch(IOException | ClassNotFoundException e) {
            System.out.println("Error reading from UserList file in order to retrieve group list");
            System.exit(-1);
        }

        //Autosave Daemon. Saves lists every 5 minutes
        AutoSave aSave = new AutoSave(this);
        aSave.setDaemon(true);
        aSave.start();

        //This block listens for connections and creates threads on new connections
        try {
            final ServerSocket serverSock = new ServerSocket(port);
            System.out.printf("%s up and running\n", this.getClass().getName());

            Socket sock = null;
            GroupThread thread = null;

            while(true) {
                sock = serverSock.accept();
                thread = new GroupThread(sock, this);
                thread.start();
            }
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }

    }

}

//This thread saves the user list AND group list (added)
class ShutDownListener extends Thread {
    public GroupServer my_gs;

    public ShutDownListener (GroupServer _gs) {
        my_gs = _gs;
    }

    public void run() {
        System.out.println("Shutting down server");
        ObjectOutputStream outStream;
        try {
            outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
            outStream.writeObject(my_gs.userList);
            // this works so it is written, problem is later
//            FileInputStream fis = new FileInputStream("UserList.bin");
//            ObjectInputStream userStream = new ObjectInputStream(fis);
//            System.out.println("Hello");
//            System.out.println(((UserList)userStream.readObject()).checkUser("admin"));

            outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
            outStream.writeObject(my_gs.groupList);
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }
}

class AutoSave extends Thread {
    public GroupServer my_gs;

    public AutoSave (GroupServer _gs) {
        my_gs = _gs;
    }

    public void run() {
        do {
            try {
                Thread.sleep(300000); //Save group and user lists every 5 minutes
                System.out.println("Autosave group and user lists...");
                ObjectOutputStream outStream;
                try {
                    outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
                    outStream.writeObject(my_gs.userList);

                    outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
                    outStream.writeObject(my_gs.groupList);
                } catch(Exception e) {
                    System.err.println("Error: " + e.getMessage());
                    e.printStackTrace(System.err);
                }

            } catch(Exception e) {
                System.out.println("Autosave Interrupted");
            }
        } while(true);
    }
}
