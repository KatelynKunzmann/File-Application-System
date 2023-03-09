import java.io.Serializable;

public class SignedToken implements Serializable {
    private final byte[] tokenBytes;
    private final byte[] tokenSignature;

    private static final long serialVersionUID = -7726335089122193103L;
    public SignedToken(byte[] tokenBytes, byte[] tokenSignature) {
        this.tokenBytes = tokenBytes;
        this.tokenSignature = tokenSignature;
    }

    public byte[] getTokenBytes() {
        return tokenBytes;
    }

    public byte[] getTokenSignature() {
        return tokenSignature;
    }
}
