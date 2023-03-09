/* FileServer loads files from FileList.bin.  Stores files in shared_files directory. */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.util.Scanner;

public class FileServer extends Server {

    public static FileList fileList;
    Scanner console = new Scanner(System.in);

    public FileServer(int _port) {
        super(_port, "omega");
    }

    public void start() {
        String fileFile = "FileList.bin";
        ObjectInputStream fileStream;

        //This runs a thread that saves the lists on program exit
        Runtime runtime = Runtime.getRuntime();
        Thread catchExit = new Thread(new ShutDownListenerFS());
        runtime.addShutdownHook(catchExit);

        //Open user file to get user list
        try {
            FileInputStream fis = new FileInputStream(fileFile);
            fileStream = new ObjectInputStream(fis);
            fileList = (FileList)fileStream.readObject();
        } catch(FileNotFoundException e) {
            System.out.println("FileList Does Not Exist. Creating FileList...");

            fileList = new FileList();

        } catch(IOException e) {
            System.out.println("Error reading from FileList file");
            System.exit(-1);
        } catch(ClassNotFoundException e) {
            System.out.println("Error reading from FileList file");
            System.exit(-1);
        }

        System.out.print("Enter the name of the file server to start or a new name to setup a new file server: ");
        String fsName = console.next();
        File pubKeyFile = new File(fsName + ".public");
        File privKeyFile = new File(fsName + ".private");
        File sharedFDir = new File(fsName + "_shared_files");
        CryptoSec cs = new CryptoSec();
        KeyPair fsKeyPair;
        Scanner in = new Scanner(System.in);
        if(!pubKeyFile.exists() || !privKeyFile.exists() || !sharedFDir.exists()) {
            System.out.println("No RSA Key Pair or shared_files directory found for " + fsName + ". " +
                   System.lineSeparator() + "If the keypair and shared_files exist elsewhere, copy '" +
                    fsName + ".public', '" + fsName + ".private', and '" + fsName + "_shared_files' directory" +
                    " into the current directory and ");
            System.out.println(" type 'y' to confirm they have been added. Otherwise, type 'n' to setup a " +
                    "new file server and generate a new RSA keypair and shared_files directory for " + fsName + ".");
            boolean validInput = false;
            while(!validInput) {
                String userInput = in.nextLine();
                if (userInput.equalsIgnoreCase("y")) {
                    if(privKeyFile.exists() && privKeyFile.exists() && sharedFDir.exists()) {
                        System.out.println("Keypair files and shared files directory found.");
                        validInput = true;
                    } else {
                        System.out.println(fsName + ".public' and/or '" + fsName + ".private' and/or" +
                                        "'" + fsName + "_shared_files' directory were not found.");
                        System.out.println("Please add the keypair files and shared files directory " +
                                "into the current directory, "+ System.lineSeparator() +"or press 'n'" +
                                " if no keypair or shared_files directory exists " +
                                "to generate a new keypair for " + fsName + " and a new shared files directory.");
                    }
                } else if (userInput.equalsIgnoreCase("n")) {
                    // Generate RSA keypair for the group server
                    fsKeyPair = cs.genRSAKeyPair();
                    cs.writeKeyPair(fsName, fsKeyPair);
                    System.out.println("An RSA Key Pair has been generated for " + fsName +
                            " and stored in files '" + fsName +
                            ".public' and '" + fsName + ".private' in the current directory.");
                    System.out.println();

                    // Write a hex version of the file server's public key to a new file,
                    // meant to be used for verification purposes
                    String pubHexString = cs.byteArrToHexStr(fsKeyPair.getPublic().getEncoded());
                    if (cs.writeStrToFile(fsName + "_pub_key_hex", pubHexString)) {
                        System.out.println("A hex version of the File Server, " + fsName + "'s public key has been"
                                + " written to " + fsName + "_pub_key_hex.txt in the current directory.");
                        System.out.println("This is meant to be given to trusted new users out-of-band as " +
                                "needed so they can verify they are connecting to the right file server.");
                    } else {
                        System.out.println("There was an error writing hex version of the file server" +
                                ", " + fsName + "'s public key to file.");
                    }
                    System.out.println();
                    if (sharedFDir.mkdir()) {
                        System.out.println("Created new shared_files directory");
                    }
                    else if (sharedFDir.exists()) {
                        System.out.println("Found shared_files directory.");
                    } else {
                        System.out.println("Error creating shared_files directory");
                    }

                    validInput = true;

                } else {
                    System.out.println("Invalid input: Please type 'y' to confirm that a keypair has been added." +
                            " Otherwise, type 'n' to setup a new file server and generate a new RSA keypair for it.");
                }
            }
        } else {
            System.out.println("Found file server keypair");
            System.out.println("Found shared_files directory");
        }


//        File file = new File(fsName + "_shared_files");
//        if (file.mkdir()) {
//            System.out.println("Created new shared_files directory");
//
//        } else if (file.exists()) {
//            System.out.println("Found shared_files directory");
//        } else {
//            System.out.println("Error creating shared_files directory");
//        }

        // File server needs group server public key upon setup
        File gsPubKeyFile = new File("gs.public");
        if (!gsPubKeyFile.exists()) {
            System.out.println("Please provide the group server's public key by adding the file 'gs.public' " +
                    System.lineSeparator() + "to the current directory to finish setting up this file server.");
            System.out.println("'gs.public' can be found in the 'known_servers' directory." +System.lineSeparator()
                    + "If it isn't there," +
                    " connect to the group server, upon first connection to the group server it will be created " +
                    "in the 'known_servers' directory.");
            System.out.println("Enter 'y' once the file is added or 'n' to cancel setup:");
            boolean validInput = false;
            while(!validInput) {
                String userInput = in.nextLine();
                if (userInput.equalsIgnoreCase("y")) {
                    if(gsPubKeyFile.exists()) {
                        System.out.println("Found group server public key file, finishing setup...");
                        validInput = true;
                    } else {
                        System.out.println("Could not find 'gs.public' in the current directory. " +
                                "Please provide the group server's public key by adding the file 'gs.public'");
                    }
                } else if (userInput.equalsIgnoreCase("n")) {
                    System.out.println("File server setup cancelled.");
                    System.exit(0);
                } else {
                    System.out.println("Invalid input: enter 'y' once the file is added or 'n' to cancel setup.");
                }
            }
        } else {
            System.out.println("Found group server public key");
        }


        //Autosave Daemon. Saves lists every 5 minutes
        AutoSaveFS aSave = new AutoSaveFS();
        aSave.setDaemon(true);
        aSave.start();

        //This block listens for connections and creates threads on new connections
        try {
            final ServerSocket serverSock = new ServerSocket(port);
            System.out.printf("%s up and running\n", this.getClass().getName());

            Socket sock = null;
            Thread thread = null;

            while(true) {
                sock = serverSock.accept();
                thread = new FileThread(sock, fsName);
                thread.start();
            }
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }
}

//This thread saves user and group lists
class ShutDownListenerFS implements Runnable {
    public void run() {
        System.out.println("Shutting down server");
        ObjectOutputStream outStream;

        try {
            outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
            outStream.writeObject(FileServer.fileList);
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }
}

class AutoSaveFS extends Thread {
    public void run() {
        do {
            try {
                Thread.sleep(300000); //Save group and user lists every 5 minutes
                System.out.println("Autosave file list...");
                ObjectOutputStream outStream;
                try {
                    outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
                    outStream.writeObject(FileServer.fileList);
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
