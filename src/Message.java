import java.io.Serializable;

public class Message implements Serializable {

    // Taken from envelope, does it matter?
    private static final long serialVersionUID = -7726335089122193104L;
    public byte[] hmac;
    public byte[] enc;
    
    public Message(byte[] h, byte[] e){
        hmac = h;
        enc = e;
    }
}
