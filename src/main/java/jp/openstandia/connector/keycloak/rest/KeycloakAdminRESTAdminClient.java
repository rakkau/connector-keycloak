/*
 *  Copyright Nomura Research Institute, Ltd.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package jp.openstandia.connector.keycloak.rest;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import com.fasterxml.jackson.jakarta.rs.json.JacksonJsonProvider;
import jp.openstandia.connector.keycloak.KeycloakClient;
import jp.openstandia.connector.keycloak.KeycloakConfiguration;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.client.jaxrs.internal.ResteasyClientBuilderImpl;
import org.jboss.resteasy.core.providerfactory.ResteasyProviderFactoryImpl;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.info.ServerInfoRepresentation;

import jakarta.ws.rs.ProcessingException;
import jakarta.ws.rs.ext.RuntimeDelegate;


import static jp.openstandia.connector.keycloak.KeycloakUtils.getRootCause;

/**
 * Keycloak client implementation which uses Keycloak Admin REST client.
 *
 * @author Hiroyuki Wada
 */
public class KeycloakAdminRESTAdminClient implements KeycloakClient {

    private static final Log LOGGER = Log.getLog(KeycloakAdminRESTAdminClient.class);

    private final String instanceName;
    private final KeycloakConfiguration cofiguration;
    private final KeycloakAdminRESTUser user;
    private final KeycloakAdminRESTGroup group;
    private final KeycloakAdminRESTClient client;
    private final KeycloakAdminRESTClientRole clientRole;
    private Keycloak adminClient;

    public KeycloakAdminRESTAdminClient(String instanceName, KeycloakConfiguration configuration) {
        this.instanceName = instanceName;
        this.cofiguration = configuration;

        try {
            RuntimeDelegate.getInstance();
        } catch (Throwable t) {
            RuntimeDelegate.setInstance(new ResteasyProviderFactoryImpl());
        }

        // ★ 1. ObjectMapper tolerante
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.configure(
                DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false
        );

        // ★ 2. Jackson provider con ese mapper
        JacksonJsonProvider jacksonProvider = new JacksonJsonProvider(objectMapper);

        ResteasyClientBuilder resteasyClientBuilder = new ResteasyClientBuilderImpl();
        resteasyClientBuilder.connectionPoolSize(20);

        // ★ 3. Registrar el provider
        resteasyClientBuilder.register(jacksonProvider);

        // HTTP proxy configuration
        if (configuration.getHttpProxyHost() != null && configuration.getHttpProxyPort() != 0) {
            final String httpProxyHost = configuration.getHttpProxyHost();

            if (StringUtil.isNotBlank(configuration.getHttpProxyUser())
                    && configuration.getHttpProxyPassword() != null) {

                configuration.getHttpProxyPassword().access(s -> {
                    String httpProxyHostWithAuth = String.format(
                            "%s:%s@%s",
                            configuration.getHttpProxyUser(),
                            String.valueOf(s),
                            httpProxyHost
                    );

                    resteasyClientBuilder.defaultProxy(
                            httpProxyHostWithAuth,
                            configuration.getHttpProxyPort(),
                            "http"
                    );
                });
            } else {
                resteasyClientBuilder.defaultProxy(
                        httpProxyHost,
                        configuration.getHttpProxyPort(),
                        "http"
                );
            }
        }

        // ★ 4. Construir UNA VEZ el ResteasyClient
        ResteasyClient resteasyClient = resteasyClientBuilder.build();

        // grant_type=password mode
        if (configuration.getUsername() != null && configuration.getPassword() != null) {
            configuration.getPassword().access(s -> {

                KeycloakBuilder adminClientBuilder = KeycloakBuilder.builder()
                        .serverUrl(configuration.getServerUrl())
                        .realm(configuration.getRealmName())
                        .grantType("password")
                        .username(configuration.getUsername())
                        .password(String.valueOf(s))
                        .clientId(configuration.getClientId())
                        // ★ 5. Usar SIEMPRE este cliente
                        .resteasyClient(resteasyClient);

                if (configuration.getClientSecret() != null) {
                    configuration.getClientSecret().access(cs ->
                            adminClientBuilder.clientSecret(String.valueOf(cs))
                    );
                }

                adminClient = adminClientBuilder.build();
            });

        } else if (configuration.getClientSecret() != null) {
            configuration.getClientSecret().access(s -> {
                adminClient = KeycloakBuilder.builder()
                        .serverUrl(configuration.getServerUrl())
                        .realm(configuration.getRealmName())
                        .grantType("client_credentials")
                        .clientId(configuration.getClientId())
                        .clientSecret(String.valueOf(s))
                        // ★ MISMO cliente REST aquí también
                        .resteasyClient(resteasyClient)
                        .build();
            });
        }

        this.user = new KeycloakAdminRESTUser(instanceName, configuration, adminClient);
        this.group = new KeycloakAdminRESTGroup(instanceName, configuration, adminClient);
        this.client = new KeycloakAdminRESTClient(instanceName, configuration, adminClient);
        this.clientRole = new KeycloakAdminRESTClientRole(instanceName, configuration, adminClient);
    }


    private RealmResource realm(String realmName) {
        return adminClient.realm(realmName);
    }

    @Override
    public void test(String realmName) {
        try {
            String realmDisplayName = adminClient.realm(realmName).toRepresentation().getDisplayName();
            if(realmDisplayName.isEmpty()){
                throw new ConnectorException("The keycloak realm isn't active.");
            }
            /*Boolean enabled = adminClient.realm(realmName).toRepresentation().isEnabled();
            if (Boolean.TRUE != enabled) {
                throw new ConnectorException("The keycloak realm isn't active.");
            }*/
        } catch (ProcessingException e) {
            // Keycloak admin-client might throw exception due to version mismatch...

            Throwable rootCause = getRootCause(e);
            if (rootCause instanceof UnrecognizedPropertyException) {
                return;
            }
            throw new ConnectorException("Failed to test the Keycloak connector.", e);
        }
    }

    @Override
    public String getVersion() {
        ServerInfoRepresentation info = adminClient.serverInfo().getInfo();
        return info.getSystemInfo().getVersion();
    }

    @Override
    public User user() {
        return user;
    }

    @Override
    public Group group() {
        return group;
    }

    @Override
    public Client client() {
        return client;
    }

    @Override
    public ClientRole clientRole() {
        return clientRole;
    }

    @Override
    public void close() {
        adminClient.close();
    }
}
