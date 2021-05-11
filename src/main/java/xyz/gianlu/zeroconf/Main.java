package xyz.gianlu.zeroconf;

import java.io.IOException;

/**
 * @author Gianlu
 */
public class Main {
    public static void main(String[] args) throws IOException {
        Zeroconf zeroconf = new Zeroconf();
        zeroconf.addAllNetworkInterfaces()
                .setUseIpv4(true)
                .setUseIpv6(false);

        Runtime.getRuntime().addShutdownHook(new Thread(zeroconf::close));

        // Announce service
        Service service = new Service(args[0], args[1], Integer.parseInt(args[2]));
        zeroconf.announce(service);

        // Start discovering
        Zeroconf.DiscoveredServices services = zeroconf.discover(args[1], "tcp", ".local");
        while (true) {
            System.out.println(services.getServices());

            try {
                Thread.sleep(1000);
            } catch (InterruptedException ex) {
                break;
            }
        }
    }
}
