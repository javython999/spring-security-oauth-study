package com.errday.springsecurityoauthstudy;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
public class IndexController {

    private final ClientRegistrationRepository clientRegistrationRepository;

    @GetMapping("/")
    public String index() {
        ClientRegistration keycloak = clientRegistrationRepository.findByRegistrationId("keycloak");
        log.info("clientId = {}", keycloak.getClientId());
        log.info("redirectUri = {}", keycloak.getRedirectUri());
        return "index";
    }
}
