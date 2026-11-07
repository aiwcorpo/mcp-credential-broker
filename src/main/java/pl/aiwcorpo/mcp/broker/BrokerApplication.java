package pl.aiwcorpo.mcp.broker;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import pl.aiwcorpo.mcp.broker.setup.BrokerSetup;

@SpringBootApplication
public class BrokerApplication {

    public static void main(String[] args) {
        if (args.length > 0 && "init".equals(args[0])) {
            System.exit(BrokerSetup.run(args));
        }
        SpringApplication.run(BrokerApplication.class, args);
    }
}
