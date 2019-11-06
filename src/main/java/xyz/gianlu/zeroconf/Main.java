package xyz.gianlu.zeroconf;

import java.io.IOException;

public class Main {

    public static void main(String[] args) throws IOException {
        Zeroconf zeroconf = new Zeroconf();
        zeroconf.addAllNetworkInterfaces();
        Service service = zeroconf.newService("MyWeb", "http", 8080)
                .putText("path", "/path/toservice").announce();

        System.out.println(service);
    }
}
