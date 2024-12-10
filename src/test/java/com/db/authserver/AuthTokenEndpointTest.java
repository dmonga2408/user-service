package com.db.authserver;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.util.Assert;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;

import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.ACCESS_TOKEN;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.GRANT_TYPE;
import static org.springframework.security.oauth2.server.authorization.oidc.OidcClientMetadataClaimNames.CLIENT_ID;
import static org.springframework.security.oauth2.server.authorization.oidc.OidcClientMetadataClaimNames.CLIENT_SECRET;

@SpringBootTest
public class AuthTokenEndpointTest {

    // NOTE: this test needs the authorization server to be running to be able to fetch the token
    @Autowired
    WebClient webClient;
    @Test
    void getAccessToken(){
        String token = webClient
                .post()
                .uri("http://localhost:9090/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(
                        BodyInserters.fromFormData(GRANT_TYPE, "client_credentials")
                                .with(CLIENT_ID, "client1")
                                .with(CLIENT_SECRET, "tempsecret1")
                                .with("scope", "profile"))
                .retrieve()
                .bodyToMono(JsonNode.class)
                .map(tokenResponse -> tokenResponse.get(ACCESS_TOKEN).textValue())
                .cache(Duration.ofMinutes(30))
                .block();
        Assert.notNull(token, "Unable to retrieve the token from the server");
        }



}
