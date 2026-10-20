import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;

/** Minimal nfbridge IPC server loop (Java 16+ Unix-domain sockets). */
public final class JavaServerLoop {

    private static final int MAGIC = 0x4E464252;      // "NFBR"
    private static final int VERSION = 1;
    private static final int TYPE_REQUEST = 1;
    private static final int TYPE_RESPONSE = 2;
    private static final int DECISION_ALLOW = 1;
    private static final int DECISION_DROP = 2;
    private static final int MAX_PAYLOAD = 65535;

    private static final String SOCKET_PATH = "/run/nfbridge/nfbridge.sock";

    public static void main(String[] args) throws IOException {
        String path = args.length > 0 ? args[0] : SOCKET_PATH;
        Path socketFile = Path.of(path);
        Files.deleteIfExists(socketFile);

        try (ServerSocketChannel server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            server.bind(UnixDomainSocketAddress.of(socketFile));
            while (true) {
                try (SocketChannel ch = server.accept();
                     var in = new DataInputStream(new BufferedInputStream(Channels.newInputStream(ch)));
                     var out = new DataOutputStream(new BufferedOutputStream(Channels.newOutputStream(ch)))) {
                    serve(in, out);
                } catch (IOException e) {
                    // nfbridge disconnected or sent a malformed request; accept the next connection.
                }
            }
        }
    }

    /** Serves one connection until nfbridge disconnects (EOF) or the stream goes bad. */
    private static void serve(DataInputStream in, DataOutputStream out) throws IOException {
        while (true) {
            if (in.readInt() != MAGIC || in.readUnsignedShort() != VERSION
                    || in.readUnsignedShort() != TYPE_REQUEST) {
                throw new IOException("bad request header");
            }
            long corr = in.readLong();
            int packetId = in.readInt();
            int hwProto = in.readUnsignedShort();
            int hook = in.readUnsignedByte();
            in.readUnsignedByte();                   // flags, reserved
            int mark = in.readInt();
            int indev = in.readInt();
            int outdev = in.readInt();
            int len = in.readInt();
            if (len < 0 || len > MAX_PAYLOAD) {
                throw new IOException("bad payload length: " + len);
            }
            byte[] packet = in.readNBytes(len);
            if (packet.length != len) {
                throw new IOException("truncated payload");
            }

            boolean allow = decide(packet, packetId, hwProto, hook, mark, indev, outdev);

            out.writeInt(MAGIC);
            out.writeShort(VERSION);
            out.writeShort(TYPE_RESPONSE);
            out.writeLong(corr);
            out.writeInt(allow ? DECISION_ALLOW : DECISION_DROP);
            out.flush();
        }
    }

    /** Your policy. */
    private static boolean decide(byte[] packet, int packetId, int hwProto, int hook,
                                  int mark, int indev, int outdev) {
        return true;
    }
}
