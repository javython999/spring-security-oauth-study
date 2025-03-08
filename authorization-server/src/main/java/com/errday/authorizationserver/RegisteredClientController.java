package com.errday.authorizationserver;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class RegisteredClientController {

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @GetMapping("/registeredClients")
    public List<RegisteredClient> registeredClients() {
        RegisteredClient registeredClient1 = registeredClientRepository.findByClientId("oauth2-client-app1");
        RegisteredClient registeredClient2 = registeredClientRepository.findByClientId("oauth2-client-app2");
        RegisteredClient registeredClient3 = registeredClientRepository.findByClientId("oauth2-client-app3");

        return List.of(registeredClient1, registeredClient2, registeredClient3);
    }
}
