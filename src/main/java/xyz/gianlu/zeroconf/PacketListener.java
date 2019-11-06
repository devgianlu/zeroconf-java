package xyz.gianlu.zeroconf;

/**
 * An interface that will be notified of a packet transmission
 * @see Zeroconf#addReceiveListener
 * @see Zeroconf#addSendListener
 */
public interface PacketListener {
    void packetEvent(Packet packet);
}
