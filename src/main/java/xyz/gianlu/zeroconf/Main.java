package xyz.gianlu.zeroconf;

import java.io.IOException;

public class Main {

    public static void main(String[] args) throws IOException {
        Zeroconf zeroconf = new Zeroconf();
        zeroconf.addAllNetworkInterfaces();

        Service service = new Service("MyWeb", "http", 8080)
                .putText("path", "/path/toservice");

        zeroconf.announce(service);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> zeroconf.unannounce(service)));
    }
}
