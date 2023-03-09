import java.util.ArrayList;


public class Envelope implements java.io.Serializable {

    /**
     *
     */
    private static final long serialVersionUID = -7726335089122193103L;
    private final String msg; // Note: the command or response such as LMEMBERS to the group server
    private final ArrayList<Object> objContents = new ArrayList<Object>(); // Note: information needed to fulfill request such as Token, etc.

    public Envelope(String text) {
        msg = text;
    }

    public String getMessage() {
        return msg;
    }

    public ArrayList<Object> getObjContents() {
        return objContents;
    }

    public void addObject(Object object) {
        objContents.add(object);
    }

}
