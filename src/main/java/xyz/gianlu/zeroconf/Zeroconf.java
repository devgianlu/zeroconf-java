package xyz.gianlu.zeroconf;

import org.apache.log4j.Logger;
import org.jetbrains.annotations.NotNull;

import java.io.Closeable;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * <p>
 * This is the root class for the Service Discovery object.
 * <p>
 * This class does not have any fancy hooks to clean up. The {@link #close} method should be called when the
 * class is to be discarded, but failing to do so won't break anything. Announced services will expire in
 * their own time, which is typically two minutes - although during this time, conforming implementations
 * should refuse to republish any duplicate services.
 * </p>
 */
@SuppressWarnings({"unused", "WeakerAccess"})
public final class Zeroconf implements Closeable {
    private static final String DISCOVERY = "_services._dns-sd._udp.local";
    private static final InetSocketAddress BROADCAST4, BROADCAST6;
    private static final Logger LOGGER = Logger.getLogger(Zeroconf.class);

    static {
        try {
            BROADCAST4 = new InetSocketAddress(InetAddress.getByName("224.0.0.251"), 5353);
            BROADCAST6 = new InetSocketAddress(InetAddress.getByName("FF02::FB"), 5353);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private final ListenerThread thread;
    private final List<Record> registry;
    private final Collection<Service> services;
    private final CopyOnWriteArrayList<PacketListener> receiveListeners;
    private final CopyOnWriteArrayList<PacketListener> sendListeners;
    private boolean useIpv4 = true;
    private boolean useIpv6 = true;
    private String hostname, domain;

    /**
     * Create a new Zeroconf object
     */
    public Zeroconf() {
        setDomain(".local");

        try {
            setLocalHostName(InetAddress.getLocalHost().getHostName());
        } catch (IOException ignored) {
        }

        receiveListeners = new CopyOnWriteArrayList<>();
        sendListeners = new CopyOnWriteArrayList<>();
        thread = new ListenerThread();
        registry = new ArrayList<>();
        services = new HashSet<>();
    }

    @NotNull
    public Zeroconf setUseIpv4(boolean ipv4) {
        this.useIpv4 = ipv4;
        return this;
    }

    @NotNull
    public Zeroconf setUseIpv6(boolean ipv6) {
        this.useIpv6 = ipv6;
        return this;
    }

    /**
     * Close down this Zeroconf object and cancel any services it has advertised.
     */
    @Override
    public void close() {
        List<Service> list = new ArrayList<>(services);
        for (Service service : list) unannounce(service);

        try {
            thread.close();
        } catch (InterruptedException ignored) {
        }
    }

    /**
     * Add a {@link PacketListener} to the list of listeners notified when a Service Discovery
     * Packet is received
     *
     * @param listener the listener
     * @return this Zeroconf
     */
    @NotNull
    public Zeroconf addReceiveListener(@NotNull PacketListener listener) {
        receiveListeners.addIfAbsent(listener);
        return this;
    }

    /**
     * Remove a previously added {@link PacketListener} from the list of listeners notified when
     * a Service Discovery Packet is received
     *
     * @param listener the listener
     * @return this Zeroconf
     */
    @NotNull
    public Zeroconf removeReceiveListener(@NotNull PacketListener listener) {
        receiveListeners.remove(listener);
        return this;
    }

    /**
     * Add a {@link PacketListener} to the list of listeners notified when a Service
     * Discovery Packet is sent
     *
     * @param listener the listener
     * @return this Zeroconf
     */
    @NotNull
    public Zeroconf addSendListener(@NotNull PacketListener listener) {
        sendListeners.addIfAbsent(listener);
        return this;
    }

    /**
     * Remove a previously added {@link PacketListener} from the list of listeners notified
     * when a Service Discovery Packet is sent
     *
     * @param listener the listener
     * @return this Zeroconf
     */
    @NotNull
    public Zeroconf removeSendListener(@NotNull PacketListener listener) {
        sendListeners.remove(listener);
        return this;
    }

    /**
     * <p>
     * Add a {@link NetworkInterface} to the list of interfaces that send and received Service
     * Discovery Packets. The interface should be up, should
     * {@link NetworkInterface#supportsMulticast} support Multicast and not be a
     * {@link NetworkInterface#isLoopback Loopback interface}. However, adding a
     * NetworkInterface that does not match this requirement will not throw an Exception - it
     * will just be ignored, as will any attempt to add a NetworkInterface that has already
     * been added.
     * </p><p>
     * All the interface's IP addresses will be added to the list of
     * {@link #getLocalAddresses local addresses}.
     * If the interface's addresses change, or the interface is otherwise modified in a
     * significant way, then it should be removed and re-added to this object. This is
     * not done automatically.
     * </p>
     *
     * @param nic a NetworkInterface
     * @return this
     * @throws IOException if something goes wrong in an I/O way
     */
    @NotNull
    public Zeroconf addNetworkInterface(@NotNull NetworkInterface nic) throws IOException {
        thread.addNetworkInterface(nic);
        return this;
    }

    @NotNull
    public Zeroconf addNetworkInterfaces(@NotNull Collection<NetworkInterface> nics) throws IOException {
        for (NetworkInterface nic : nics) thread.addNetworkInterface(nic);
        return this;
    }

    /**
     * Remove a {@link #addNetworkInterface previously added} NetworkInterface from this
     * object's list. The addresses that were part of the interface at the time it was added
     * will be removed from the list of {@link #getLocalAddresses local addresses}.
     *
     * @param nic a NetworkInterface
     * @return this
     * @throws IOException if something goes wrong in an I/O way
     */
    @NotNull
    public Zeroconf removeNetworkInterface(@NotNull NetworkInterface nic) throws IOException {
        thread.removeNetworkInterface(nic);
        return this;
    }

    /**
     * A convenience method to add all local NetworkInterfaces - it simply runs
     * <pre>
     * for (Enumeration&lt;NetworkInterface&gt; e = NetworkInterface.getNetworkInterfaces();e.hasMoreElements();) {
     *     addNetworkInterface(e.nextElement());
     * }
     * </pre>
     *
     * @return this
     * @throws IOException if something goes wrong in an I/O way
     */
    @NotNull
    public Zeroconf addAllNetworkInterfaces() throws IOException {
        for (Enumeration<NetworkInterface> e = NetworkInterface.getNetworkInterfaces(); e.hasMoreElements(); )
            addNetworkInterface(e.nextElement());

        return this;
    }

    /**
     * Get the Service Discovery Domain, which is set by {@link #setDomain}. It defaults to ".local",
     * but can be set by {@link #setDomain}
     *
     * @return the domain
     */
    public String getDomain() {
        return domain;
    }

    /**
     * Set the Service Discovery Domain
     *
     * @param domain the domain
     * @return this
     */
    @NotNull
    public Zeroconf setDomain(@NotNull String domain) {
        this.domain = domain;
        return this;
    }

    /**
     * Get the local hostname, which defaults to <code>InetAddress.getLocalHost().getHostName()</code>.
     *
     * @return the local host name
     */
    public String getLocalHostName() {
        if (hostname == null) throw new IllegalStateException("Hostname cannot be determined");
        return hostname;
    }

    /**
     * Set the local hostname, as returned by {@link #getLocalHostName}
     *
     * @param name the hostname, which should be undotted
     * @return this
     */
    @NotNull
    public Zeroconf setLocalHostName(@NotNull String name) {
        this.hostname = name;
        return this;
    }

    /**
     * Return a list of InetAddresses which the Zeroconf object considers to be "local". These
     * are the all the addresses of all the {@link NetworkInterface} objects added to this
     * object. The returned list is a copy, it can be modified and will not be updated
     * by this object.
     *
     * @return a List of local {@link InetAddress} objects
     */
    public List<InetAddress> getLocalAddresses() {
        return thread.getLocalAddresses();
    }

    /**
     * Send a packet
     */
    public void send(@NotNull Packet packet) {
        thread.push(packet);
    }

    /**
     * Return the registry of records. This is the list of DNS records that we will
     * automatically match any queries against. The returned list is live.
     */
    public List<Record> getRegistry() {
        return registry;
    }

    /**
     * Return the list of all Services that have been {@link Zeroconf#announce} announced
     * by this object. The returned Collection is read-only and live, so will be updated
     * by this object.
     *
     * @return the Collection of announced Services
     */
    public Collection<Service> getAnnouncedServices() {
        return Collections.unmodifiableCollection(services);
    }

    /**
     * Given a query packet, trawl through our registry and try to find any records that
     * match the queries. If there are any, send our own response packet.
     * <p>
     * This is largely derived from other implementations, but broadly the logic here is
     * that questions are matched against records based on the "name" and "type" fields,
     * where {@link #DISCOVERY} and {@link Record#TYPE_ANY} are wildcards for those
     * fields. Currently we match against all packet types - should these be just "PTR"
     * records?
     * <p>
     * Once we have this list of matched records, we search this list for any PTR records
     * and add any matching SRV or TXT records (RFC 6763 12.1). After that, we scan our
     * updated list and add any A or AAAA records that match any SRV records (12.2).
     * <p>
     * At the end of all this, if we have at least one record, send it as a response
     */
    private void handlePacket(@NotNull Packet packet) {
        Packet response = null;
        Set<String> targets = null;
        for (Record question : packet.getQuestions()) {
            for (Record record : getRegistry()) {
                if ((question.getName().equals(DISCOVERY) || question.getName().equals(record.getName())) && (question.getType() == record.getType() || question.getType() == Record.TYPE_ANY && record.getType() != Record.TYPE_NSEC)) {
                    if (response == null) {
                        response = new Packet(packet.getID());
                        response.setAuthoritative(true);
                    }

                    response.addAnswer(record);
                    if (record instanceof RecordSRV) {
                        if (targets == null) targets = new HashSet<>();
                        targets.add(((RecordSRV) record).getTarget());
                    }
                }
            }

            if (response != null && question.getType() != Record.TYPE_ANY) {
                // When including a DNS-SD Service Instance Enumeration or Selective
                // Instance Enumeration (subtype) PTR record in a response packet, the
                // server/responder SHOULD include the following additional records:
                // o The SRV record(s) named in the PTR rdata.
                // o The TXT record(s) named in the PTR rdata.
                // o All address records (type "A" and "AAAA") named in the SRV rdata.
                for (Record answer : response.getAnswers()) {
                    if (answer.getType() != Record.TYPE_PTR)
                        continue;

                    for (Record record : getRegistry()) {
                        if (record.getName().equals(((RecordPTR) answer).getValue())
                                && (record.getType() == Record.TYPE_SRV || record.getType() == Record.TYPE_TXT)) {
                            response.addAdditional(record);
                            if (record instanceof RecordSRV) {
                                if (targets == null) targets = new HashSet<>();
                                targets.add(((RecordSRV) record).getTarget());
                            }
                        }
                    }
                }
            }
        }

        if (response != null) {
            // When including an SRV record in a response packet, the
            // server/responder SHOULD include the following additional records:
            // o All address records (type "A" and "AAAA") named in the SRV rdata.
            if (targets != null) {
                for (String target : targets) {
                    for (Record record : getRegistry()) {
                        if (record.getName().equals(target) && (record.getType() == Record.TYPE_A || record.getType() == Record.TYPE_AAAA)) {
                            response.addAdditional(record);
                        }
                    }
                }
            }

            send(response);
        }
    }

    /**
     * Probe for a ZeroConf service with the specified name and return true if a matching
     * service is found.
     * <p>
     * The approach is borrowed from https://www.npmjs.com/package/bonjour - we send three
     * broadcasts trying to match the service name, 250ms apart. If we receive no response,
     * assume there is no service that matches
     * <p>
     * Note the approach here is the only example of where we send a query packet. It could
     * be used as the basis for us acting as a service discovery client
     *
     * @param fqdn the fully qualified servicename, eg "My Web Service._http._tcp.local".
     */
    private boolean probe(final String fqdn) {
        final Packet probe = new Packet();
        probe.setResponse(false);
        probe.addQuestion(new RecordANY(fqdn));
        final AtomicBoolean match = new AtomicBoolean(false);
        PacketListener probeListener = packet -> {
            if (packet.isResponse()) {
                for (Record r : packet.getAnswers()) {
                    if (r.getName().equalsIgnoreCase(fqdn)) {
                        synchronized (match) {
                            match.set(true);
                            match.notifyAll();
                        }
                    }
                }

                for (Record r : packet.getAdditionals()) {
                    if (r.getName().equalsIgnoreCase(fqdn)) {
                        synchronized (match) {
                            match.set(true);
                            match.notifyAll();
                        }
                    }
                }
            }
        };

        addReceiveListener(probeListener);
        for (int i = 0; i < 3 && !match.get(); i++) {
            send(probe);
            synchronized (match) {
                try {
                    match.wait(250);
                } catch (InterruptedException ex) {
                    // ignore
                }
            }
        }

        removeReceiveListener(probeListener);
        return match.get();
    }

    /**
     * Announce the service - probe to see if it already exists and fail if it does, otherwise
     * announce it
     */
    public void announce(@NotNull Service service) {
        if (service.getDomain() == null) service.setDomain(getDomain());
        if (service.getHost() == null) service.setHost(getLocalHostName());
        if (!service.hasAddresses()) service.addAddresses(getLocalAddresses());

        Packet packet = service.getPacket();
        if (probe(service.getInstanceName()))
            throw new IllegalArgumentException("Service " + service.getInstanceName() + " already on network");

        getRegistry().addAll(packet.getAnswers());
        services.add(service);

        for (int i = 0; i < 3; i++) {
            send(packet);

            try {
                Thread.sleep(225);
            } catch (InterruptedException ignored) {
            }
        }

        LOGGER.info("Announced service: " + service);
    }

    /**
     * Unannounce the service. Do this by re-announcing all our records but with a TTL of 0 to
     * ensure they expire. Then remove from the registry.
     */
    public void unannounce(@NotNull Service service) {
        Packet packet = service.getPacket();
        getRegistry().removeAll(packet.getAnswers());
        for (Record r : packet.getAnswers()) {
            getRegistry().remove(r);
            r.setTTL(0);
        }

        services.remove(service);

        for (int i = 0; i < 3; i++) {
            send(packet);

            try {
                Thread.sleep(125);
            } catch (InterruptedException ignored) {
            }
        }


        LOGGER.info("Unannounced service. " + service);
    }

    /**
     * The thread that listens to one or more Multicast DatagramChannels using a Selector,
     * waiting for incoming packets. This wait can be also interrupted and a packet sent.
     */
    private class ListenerThread extends Thread {
        private final Deque<Packet> sendq;
        private final Map<NetworkInterface, SelectionKey> channels;
        private final Map<NetworkInterface, List<InetAddress>> localAddresses;
        private volatile boolean cancelled;
        private Selector selector;

        ListenerThread() {
            super("zeroconf-io-thread");

            setDaemon(false);
            sendq = new ArrayDeque<>();
            channels = new HashMap<>();
            localAddresses = new HashMap<>();
        }

        private synchronized Selector getSelector() throws IOException {
            if (selector == null) selector = Selector.open();
            return selector;
        }

        /**
         * Stop the thread and rejoin
         */
        synchronized void close() throws InterruptedException {
            this.cancelled = true;
            if (selector != null) {
                selector.wakeup();
                if (isAlive()) join();
            }
        }

        /**
         * Add a packet to the send queue
         */
        synchronized void push(Packet packet) {
            sendq.addLast(packet);
            if (selector != null) {
                // Only send if we have a Nic
                selector.wakeup();
            }
        }

        /**
         * Pop a packet from the send queue or return null if none available
         */
        private synchronized Packet pop() {
            return sendq.pollFirst();
        }

        /**
         * Add a NetworkInterface. Try to identify whether it's IPV4 or IPV6, or both. IPV4 tested,
         * IPV6 is not but at least it doesn't crash.
         */
        public synchronized void addNetworkInterface(@NotNull NetworkInterface nic) throws IOException {
            if (!channels.containsKey(nic) && nic.supportsMulticast() && nic.isUp() && !nic.isLoopback()) {
                boolean ipv4 = false, ipv6 = false;
                List<InetAddress> locallist = new ArrayList<>();
                for (Enumeration<InetAddress> e = nic.getInetAddresses(); e.hasMoreElements(); ) {
                    InetAddress a = e.nextElement();
                    if ((a instanceof Inet4Address && !useIpv4) || (a instanceof Inet6Address && !useIpv6))
                        continue;

                    ipv4 |= a instanceof Inet4Address;
                    ipv6 |= a instanceof Inet6Address;
                    if (!a.isLoopbackAddress() && !a.isMulticastAddress())
                        locallist.add(a);
                }

                DatagramChannel channel = DatagramChannel.open(StandardProtocolFamily.INET);
                channel.configureBlocking(false);
                channel.setOption(StandardSocketOptions.SO_REUSEADDR, true);
                channel.setOption(StandardSocketOptions.IP_MULTICAST_TTL, 255);
                if (ipv4) {
                    channel.bind(new InetSocketAddress(BROADCAST4.getPort()));
                    channel.setOption(StandardSocketOptions.IP_MULTICAST_IF, nic);
                    channel.join(BROADCAST4.getAddress(), nic);
                } else if (ipv6) {
                    channel.bind(new InetSocketAddress(BROADCAST6.getPort()));
                    channel.join(BROADCAST6.getAddress(), nic);
                }

                channels.put(nic, channel.register(getSelector(), SelectionKey.OP_READ));
                localAddresses.put(nic, locallist);
                if (!isAlive()) start();
            }
        }

        synchronized void removeNetworkInterface(@NotNull NetworkInterface nic) throws IOException {
            SelectionKey key = channels.remove(nic);
            if (key != null) {
                localAddresses.remove(nic);
                key.channel().close();
                getSelector().wakeup();
            }
        }

        synchronized List<InetAddress> getLocalAddresses() {
            List<InetAddress> list = new ArrayList<>();
            for (List<InetAddress> pernic : localAddresses.values()) {
                for (InetAddress address : pernic) {
                    if (!list.contains(address))
                        list.add(address);
                }
            }

            return list;
        }

        @Override
        public void run() {
            ByteBuffer buf = ByteBuffer.allocate(65536);
            buf.order(ByteOrder.BIG_ENDIAN);
            while (!cancelled) {
                buf.clear();
                try {
                    Packet packet = pop();
                    if (packet != null) {
                        // Packet to Send
                        buf.clear();
                        packet.write(buf);
                        buf.flip();
                        for (PacketListener listener : sendListeners)
                            listener.packetEvent(packet);

                        for (SelectionKey key : channels.values()) {
                            DatagramChannel channel = (DatagramChannel) key.channel();
                            InetSocketAddress address = packet.getAddress();
                            if (address != null) {
                                channel.send(buf, address);
                            } else {
                                if (useIpv4) channel.send(buf, BROADCAST4);
                                if (useIpv6) channel.send(buf, BROADCAST6);
                            }
                        }
                    }

                    // We know selector exists
                    Selector selector = getSelector();
                    selector.select();
                    Set<SelectionKey> selected = selector.selectedKeys();
                    for (SelectionKey key : selected) {
                        // We know selected keys are readable
                        DatagramChannel channel = (DatagramChannel) key.channel();
                        InetSocketAddress address = (InetSocketAddress) channel.receive(buf);
                        if (address != null && buf.position() != 0) {
                            buf.flip();
                            packet = new Packet();
                            packet.read(buf, address);
                            for (PacketListener listener : receiveListeners)
                                listener.packetEvent(packet);
                            handlePacket(packet);
                        }
                    }

                    selected.clear();
                } catch (Exception ex) {
                    LOGGER.warn("Failed receiving/sending packet!", ex);
                }
            }
        }
    }
}
