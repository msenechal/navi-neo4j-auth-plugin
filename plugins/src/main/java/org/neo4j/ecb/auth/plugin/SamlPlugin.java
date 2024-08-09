/**
 * Copyright (c) 2002-2017 "Neo Technology,"
 * Network Engine for Objects in Lund AB [http://neotechnology.com]
 *
 * This file is part of Neo4j.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.neo4j.ecb.auth.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.neo4j.server.security.enterprise.auth.plugin.api.AuthProviderOperations;
import com.neo4j.server.security.enterprise.auth.plugin.api.AuthToken;
import com.neo4j.server.security.enterprise.auth.plugin.api.AuthenticationException;
import com.neo4j.server.security.enterprise.auth.plugin.spi.AuthInfo;
import com.neo4j.server.security.enterprise.auth.plugin.spi.AuthPlugin;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.neo4j.configuration.GraphDatabaseSettings;
import org.neo4j.graphdb.GraphDatabaseService;
import org.neo4j.internal.helpers.collection.Iterators;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.*;

public class SamlPlugin extends AuthPlugin.Adapter
{
    AuthProviderOperations api;
    URI validationUri;
    CloseableHttpClient httpClient;
    String defaultRole;
    GraphDatabaseService systemDb;
    private static final String ROLE_CLAIM = "roles";

    @Override
    public AuthInfo authenticateAndAuthorize(AuthToken authToken) throws AuthenticationException {
        String username = authToken.principal();
        String password = new String(authToken.credentials());

        api.log().info("Log in attempted for user '" + username + "'.");

        HttpGet request = new HttpGet(validationUri);
        request.setHeader("Authorization", "Bearer " + password);

        List<String> roles;

        try (CloseableHttpResponse response = httpClient.execute(request, new HttpClientContext())) {
            roles = handleHttpResponse(response, username);
            return AuthInfo.of(username, roles);
        } catch (IOException e) {
            throw new AuthenticationException(e.getMessage());
        }
    }

    List<String> handleHttpResponse(CloseableHttpResponse response, String username) throws IOException, AuthenticationException {
        int statusCode = response.getStatusLine().getStatusCode();
        api.log().debug("HTTP request status: " + statusCode);

        if (statusCode == HttpStatus.SC_OK) {
            return handleSuccessResponse(response, username);
        } else if (statusCode == HttpStatus.SC_SEE_OTHER) {
            throw new AuthenticationException("Unauthorized (401)");
        } else {
            throw new AuthenticationException("unexpected http status " + response.getStatusLine().toString());
        }
    }

    List<String> handleSuccessResponse(CloseableHttpResponse response, String username) throws IOException, AuthenticationException {
        String responseBody = EntityUtils.toString(response.getEntity());

        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(responseBody);

        List<String> roles = extractRoles(jsonNode, username);

        api.log().info("Log in success for user '" + username + "' with roles: " + roles + ".");
        return roles;
    }

    List<String> extractRoles(JsonNode jsonNode, String username) throws AuthenticationException {
        List<String> roles = new ArrayList<>();

        if (jsonNode == null) {
            api.log().error("JsonNode is null for user: " + username);
            throw new AuthenticationException("Invalid response for principal " + username);
        }

        if (jsonNode.has(ROLE_CLAIM) && jsonNode.get(ROLE_CLAIM).isArray()) {
            JsonNode rolesNode = jsonNode.get(ROLE_CLAIM);
            for (JsonNode role : rolesNode) {
                roles.add(role.asText().replace("-", "__"));
            }
        }

        api.log().debug("Extracted roles from JSON: " + roles);

        List<String> dbRoles = findRolesInSystemDbFor(username);
        api.log().debug("Roles found in database: " + dbRoles);

        roles.addAll(dbRoles);

        if (roles.isEmpty() && (defaultRole != null)) {
            roles.add(defaultRole);
        }

        api.log().debug("Final roles for user " + username + ": " + roles);

        return roles;
    }

    List<String> findRolesInSystemDbFor(String principal) {
        return systemDb.executeTransactionally("show users where user=$user", Collections.singletonMap("user", principal),
                result -> {
                    Map<String, Object> map = Iterators.singleOrNull(result);
                    return map == null ? Collections.emptyList() : (List<String>) map.get(ROLE_CLAIM);
                });
    }

    @Override
    public void initialize(AuthProviderOperations authProviderOperations) {
        this.api = authProviderOperations;
        if (this.api != null && this.api.log() != null) {
            this.api.log().info("ECB SAML plugin initialized.");
        }
        try {
            loadConfig();
        } catch (URISyntaxException e) {
            this.api.log().info("Could not load SAML configs: " + e);
        }
    }

    void loadConfig() throws URISyntaxException {
        Path configFile = resolveConfigFilePath();
        Properties properties = loadProperties( configFile );

        this.validationUri = new URI(properties.getProperty( "plugins.auth.saml.validation_url" ));
        this.defaultRole = properties.getProperty("plugins.auth.saml.default_role");

        api.log().info( "plugins.auth.saml.validation_url=" + validationUri );
        api.log().info( "plugins.auth.saml.default_role=" + defaultRole );
    }

    Path resolveConfigFilePath()
    {
        return api.neo4jHome().resolve( "conf/saml.conf" );
    }

    Properties loadProperties(Path configFile) {
        Properties properties = new Properties();
        try (InputStream inputStream = getInputStream(configFile)) {
            properties.load(inputStream);
        } catch (IOException e) {
            api.log().error("Failed to load config file '" + configFile + "': " + e.getMessage());
        }
        return properties;
    }

    InputStream getInputStream(Path configFile) throws IOException {
        return new FileInputStream(configFile.toFile());
    }

    @Override
    public void start() {
        this.systemDb = ExposeConfigExtensionFactory.getDbms().database(GraphDatabaseSettings.SYSTEM_DATABASE_NAME);

        this.httpClient = HttpClients.custom()
                .disableCookieManagement()
                .disableRedirectHandling()
                .build();
    }

}
