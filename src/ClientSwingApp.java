import javax.swing.*;
import java.awt.event.*;
import java.util.List;
import java.awt.Color;
import java.awt.GridLayout;
import java.awt.Font;


public class ClientSwingApp extends JFrame {

    GroupClient gClient;
    FileClient fClient;
    SignedToken token;
    String username;
    JFrame frame;

    ClientSwingApp(){
        gClient = new GroupClient();
        fClient = new FileClient();
        token = null;
        frame =  new JFrame();

        frame.setTitle("Group-Based File Sharing Application");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        username=JOptionPane.showInputDialog(frame,"Enter User Name");

        JTextArea ta = new JTextArea();

        ta.setBounds(270, 20,400, 420);
        JTabbedPane tabButtonPane = new JTabbedPane();
        Font font = new Font(Font.MONOSPACED, Font.BOLD, 12);
        ta.setFont(font);
        ta.setLayout(new GridLayout(1, 1, 10, 10));
        ta.setBackground(Color.LIGHT_GRAY);

        JScrollPane scrollPane = new JScrollPane(ta);
        scrollPane.setBounds(275, 20, 485, 420);
        scrollPane.setVisible(true);
        frame.add(scrollPane);

        JButton b1=new JButton("Connect to File Server");
        b1.setBounds(0,0,200,50);
        b1.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
                String server = JOptionPane.showInputDialog(frame,"Enter File Server");
                int port = Integer.parseInt(JOptionPane.showInputDialog(frame,"Enter Port"));
                // TODO commented to allow it to compile
//         original line       fClient.connect(server,port);
                ta.append("Connected to file server: " + server + " on port " + port + "\n");
            }
        });

        JButton b2=new JButton("Connect to Group Server");
        b2.setBounds(200,0,200,50);
        b2.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
                String server = JOptionPane.showInputDialog(frame,"Enter Group Server");
                int port = Integer.parseInt(JOptionPane.showInputDialog(frame,"Enter Port"));
                // TODO commented to enable it to compile without private key
                // original: gClient.connect(server,port);
                ta.append("Connected to group server: " + server + " on port " + port + "\n");
            }
        });

        JButton b3=new JButton("Get Token");
        b3.setBounds(400,0,200,50);
        b3.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
                if(username != null && gClient.isConnected()) {
                    // TODO fix to work with t7
//                    token = gClient.getToken(username);
                    if (token != null) {
                        ta.append("Token Recieved \n");
                    } else {
                        ta.append("Request for token failed.\n");
                    }
                }
            }
        });

        JButton b4=new JButton("Create Group");
        b4.setBounds(600,0,200,50);
        b4.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
                if (gClient.isConnected()) {
                    if (token != null) {
                        String groupname = JOptionPane.showInputDialog(frame,"Enter Group Name\n");
                        if (!gClient.createGroup(groupname, token)){
                            ta.append("Failed to create group.\n");
                        } else {
                            ta.append("Group " + groupname + " created.\n");
                        }

                    } else {
                        ta.append("Token required to create group. Please get a token first using gettoken\n");
                    }
                }
                else {
                    ta.append("Connect to a group server first.\n");
                }
            }
        });

        JButton b5=new JButton("Create User");
        b5.setBounds(800,0,200,50);
        b5.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
                if (username != null && gClient.isConnected()) {
                    // if (username.equals("ADMIN")) { // Security measure on client side as well
                        if (token != null) {
                            String cname = JOptionPane.showInputDialog(frame,"Enter Name");
                            if (!gClient.createUser(cname, token)){
                                ta.append("Failed to create user.\n");
                            } else {
                                ta.append("User " + cname + " created.\n");
                            }

                        } else {
                            ta.append("Token required to create username.\n");
                        }
                    // } else {
                    //     ta.append("Permission Denied.\n");
                    // }
                }
            }
        });

        JButton b6=new JButton("Delete Group");
        b6.setBounds(0,75,200,50);
        b6.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
                if (gClient.isConnected()) {
                    if (token != null) {
                        String groupname = JOptionPane.showInputDialog(frame,"Enter Group Name");
                        if (!gClient.deleteGroup(groupname, token)){
                            ta.append("Failed to delete group.\n");
                        } else {
                            ta.append("Group " + groupname + " deleted.\n");
                        }
                    } else {
                        ta.append("Token required to delete group. Please get a token first using gettoken\n");
                    }
                }
                else {
                    ta.append("Connect to a group server first.\n");
                }
            }
        });

        JButton b7=new JButton("Delete User");
        b7.setBounds(200,75,200,50);
        b7.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
                if (username != null && gClient.isConnected()) {
                    // if (username.equals("ADMIN")) { // Security measure on client side as well
                        if (token != null) {
                            String cname = JOptionPane.showInputDialog(frame,"Enter Name");

                            if (!gClient.deleteUser(cname, token)){
                                ta.append("Failed to delete user.\n");
                            } else {
                                ta.append("User " + cname+ " deleted.\n");
                            }

                        } else {
                            ta.append("Token required to create username. Please get a token first using gettoken\n");
                        }
                    // } else {
                    //     ta.append("Permission Denied.\n");
                    // }
                }
            }
        });

        JButton b8=new JButton("Add User to Group");
        b8.setBounds(400,75,200,50);
        b8.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
                if (gClient.isConnected()) {
                    if (token != null) {
                        String cname = JOptionPane.showInputDialog(frame,"Enter Name");
                        String groupname = JOptionPane.showInputDialog(frame,"Enter Group Name");
                        if (!gClient.addUserToGroup(cname, groupname, token)){
                            ta.append("Failed to add " + cname + " to " + groupname + ".\n");
                        } else {
                            ta.append(cname + " added to " + groupname + ".\n");
                        }

                    } else {
                        ta.append("Valid token required to add user to group. Please get a token first using gettoken.\n");
                    }
                }
                else {
                    ta.append("Connect to a group server first.\n");
                }
            }
        });

        JButton b9=new JButton("Delete User From Group");
        b9.setBounds(600,75,200,50);
        b9.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
                if (gClient.isConnected()) {
                    if (token != null) {
                        String cname = JOptionPane.showInputDialog(frame,"Enter Name");
                        String groupname = JOptionPane.showInputDialog(frame,"Enter Group Name");
                        if (!gClient.deleteUserFromGroup(cname,groupname, token)){
                            ta.append("Failed to delete " + cname + " from " + groupname + ".\n");
                        } else {
                            ta.append(cname + " deleted from " + groupname + ".\n");
                        }

                    } else {
                        ta.append("Valid token required to delete user from group. Please get a token first using gettoken.\n");
                    }
                }
                else {
                    ta.append("Connect to a group server first.\n");
                }

            }
        });

        JButton b10=new JButton("List Group Members");
        b10.setBounds(800,50,200, 50);
        b10.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
                if (gClient.isConnected()) {
                    if (token != null) {
                        String groupname = JOptionPane.showInputDialog(frame,"Enter Group Name");
                        List<String> members = gClient.listMembers(groupname, token);
                        if (members != null) {
                            ta.append("There are " + members.size() + " members.\n");
                            for (String member : members) {
                                ta.append(member+"\n");
                            }
                        } else {
                            ta.append("Failed to get list of members.\n");
                        }

                    } else {
                        ta.append("Valid token required to list group members. Please get a token first using gettoken.\n");
                    }
                } else {
                    ta.append("Connect to a group server first.\n");
                }
            }
        });

        JButton b11=new JButton("Download");
        b11.setBounds(0,150,200,75);
        b11.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
                if (fClient.isConnected()) {
                    if (token != null) {
                        String src = JOptionPane.showInputDialog(frame,"Enter Source File");
                        String dest = JOptionPane.showInputDialog(frame,"Enter Destination File");
                        boolean isdownloaded = fClient.download(src, dest, token);
                        if(!isdownloaded) {
                            ta.append("Failed to download file.\n");
                        }
                    } else {
                        ta.append("Valid token required to download file. Please get a token first using gettoken.\n");
                    }
                } else {
                    ta.append("Connect to a file server first.\n");
                }
            }
        });

        JButton b12=new JButton("Upload");
        b12.setBounds(200,150,200,75);
        b12.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
                if (fClient.isConnected()) {
                    if (token != null) {
                        String src = JOptionPane.showInputDialog(frame,"Enter Source File");
                        String dest = JOptionPane.showInputDialog(frame,"Enter Destination File");
                        String groupname = JOptionPane.showInputDialog(frame,"Enter Group Name");
                        boolean isuploaded = fClient.upload(src, dest, groupname, token);
                        if(!isuploaded) {
                            ta.append("Failed to upload file.\n");
                        }
                    } else {
                        ta.append("Valid token required to upload file to group. Please get a token first using gettoken.\n");
                    }
                } else {
                    ta.append("Connect to a file server first.\n");
                }
            }
        });

        JButton b13=new JButton("Delete");
        b13.setBounds(400,150,200,75);
        b13.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
                if (fClient.isConnected()) {
                    if (token != null) {
                        String src = JOptionPane.showInputDialog(frame,"Enter File");
                        boolean isdeleted = fClient.delete(src, token);
                        if(!isdeleted) {
                            ta.append("Failed to delete file.\n");
                        }
                        else {
                            ta.append(src + " deleted.\n");
                        }

                    } else {
                        ta.append("Valid token required to delete file. Please get a token first using gettoken.\n");
                    }
                } else {
                    ta.append("Connect to a file server first.\n");
                }
            }
        });

        JButton b14=new JButton("List Files");
        b14.setBounds(600,150,200,75);
        b14.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
                if (fClient.isConnected()) {
                    if (token != null) {
                        List<String> files = fClient.listFiles(token);
                        ta.append("There are " + files.size() + " files.\n");
                        for (String file : files) {
                            ta.append(file+"\n");
                        }
                    } else {
                        ta.append("Valid token required to list files. Please get a token first using gettoken.\n");
                    }
                } else {
                    ta.append("Connect to a file server first.\n");
                }
            }
        });

        ActionListener disconnectListener =  new ActionListener(){
            public void actionPerformed(ActionEvent e){
                gClient.disconnect();
                ta.append("Disconnected from group server\n");
                System.out.println("Disconnected from group server");
                fClient.disconnect();
                ta.append("Disconnected from file server(s)\n");
                System.out.println("Disconnected from file server");
            }
        };
        JButton b15=new JButton("Disconnect");
        b15.setBounds(800,150,300,50);
        b15.addActionListener(disconnectListener);

        JButton b17 = new JButton("Disconnect");
        b17.setBounds(800,150,300,50);
        b17.addActionListener(disconnectListener);

        ActionListener relogListener = new ActionListener(){
            public void actionPerformed(ActionEvent e) {
                ta.setText(null);
                login();
            }
        };
        JButton b16 = new JButton("Relog"); // could technically remove relog from filer server options
        b16.setBounds(100, 150, 300, 50);
        b16.addActionListener(relogListener);

        JButton bGRelog = new JButton("Relog");
        bGRelog.setBounds(100, 150, 300, 50);
        bGRelog.addActionListener(relogListener);


        JPanel groupButtons = new JPanel();
        groupButtons.add(b2);
        groupButtons.add(b3);
        groupButtons.add(b4);
        groupButtons.add(b5);
        groupButtons.add(b6);
        groupButtons.add(b7);
        groupButtons.add(b8);
        groupButtons.add(b9);
        groupButtons.add(b10);
        groupButtons.add(bGRelog);
        groupButtons.add(b15);


        JPanel fileButtons = new JPanel();
        fileButtons.add(b1);
        fileButtons.add(b11);
        fileButtons.add(b12);
        fileButtons.add(b13);
        fileButtons.add(b14);
        fileButtons.add(b16);
        fileButtons.add(b17);

        groupButtons.setLayout(new GridLayout(12, 1, 5, 5));
        fileButtons.setLayout(new GridLayout(10, 1, 5, 5));

        tabButtonPane.addTab("Group Server", groupButtons);
        tabButtonPane.addTab("File Server", fileButtons);
        tabButtonPane.setSize(250, 500);

        frame.add(tabButtonPane);
        tabButtonPane.setVisible(true);
        frame.setSize(800, 500);
        frame.setLayout(null); // using no layout managers
        frame.setVisible(true);
    }

    public boolean login() {
        // In case of relogging, close out previous session.
        token = null;
        username = null;
        if(gClient != null && gClient.isConnected()){
            gClient.disconnect();
            gClient = null;
        }
        if(fClient != null && fClient.isConnected()){
            fClient.disconnect();
            fClient = null;
        }

        username=JOptionPane.showInputDialog(frame,"Enter User Name");

        gClient = new GroupClient();
        fClient = new FileClient();

        return true; // For now there are no checks
    }

    public static void main(String[] args) {
        new ClientSwingApp();
    }
}
