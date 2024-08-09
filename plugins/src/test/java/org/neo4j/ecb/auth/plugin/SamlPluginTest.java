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
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.neo4j.server.security.enterprise.auth.plugin.api.AuthProviderOperations;
import com.neo4j.server.security.enterprise.auth.plugin.api.AuthToken;
import com.neo4j.server.security.enterprise.auth.plugin.api.AuthenticationException;
import com.neo4j.server.security.enterprise.auth.plugin.spi.AuthInfo;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.neo4j.configuration.GraphDatabaseSettings;
import org.neo4j.dbms.api.DatabaseManagementService;
import org.neo4j.graphdb.GraphDatabaseService;
import org.neo4j.graphdb.Result;
import org.neo4j.graphdb.Transaction;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;

import java.util.Map;
import java.util.*;


public class SamlPluginTest {

    private SamlPlugin samlPlugin;

    @Mock private AuthProviderOperations authProviderOperations;
    @Mock private AuthProviderOperations.Log log;
    @Mock private AuthToken authToken;
    @Mock private CloseableHttpClient httpClient;
    @Mock private CloseableHttpResponse httpResponse;
    @Mock private DatabaseManagementService dbms;
    @Mock private GraphDatabaseService systemDb;
    @Mock private Transaction transaction;
    @Mock private Result result;

    private static final String ROLE_CLAIM = "roles";

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        samlPlugin = spy(new SamlPlugin());

        when(authProviderOperations.log()).thenReturn(log);

        Path mockPath = mock(Path.class);
        when(authProviderOperations.neo4jHome()).thenReturn(mockPath);
        when(mockPath.resolve(anyString())).thenReturn(mockPath);

        Properties mockProperties = new Properties();
        mockProperties.setProperty("plugins.auth.saml.validation_url", "https://example.com/validate");
        mockProperties.setProperty("plugins.auth.saml.default_role", "defaultRole");
        doReturn(mockProperties).when(samlPlugin).loadProperties(any(Path.class));

        samlPlugin.initialize(authProviderOperations);

        samlPlugin.validationUri = new URI("https://example.com/validate");
        samlPlugin.httpClient = httpClient;
        when(dbms.database(GraphDatabaseSettings.SYSTEM_DATABASE_NAME)).thenReturn(systemDb);
        samlPlugin.systemDb = systemDb;
    }

    @Test
    public void testAuthenticateAndAuthorize() throws Exception {
        when(authToken.principal()).thenReturn("testUser");
        when(authToken.credentials()).thenReturn("testToken".toCharArray());

        HttpEntity mockEntity = mock(HttpEntity.class);
        String jsonResponse = "{\"roles\": [\"testRole\"]}";
        InputStream inputStream = new ByteArrayInputStream(jsonResponse.getBytes());
        when(mockEntity.getContent()).thenReturn(inputStream);
        when(httpResponse.getEntity()).thenReturn(mockEntity);
        when(httpResponse.getStatusLine()).thenReturn(mock(StatusLine.class));
        when(httpResponse.getStatusLine().getStatusCode()).thenReturn(HttpStatus.SC_OK);
        when(httpClient.execute(any(HttpGet.class), any(HttpClientContext.class))).thenReturn(httpResponse);

        List<String> dbRoles = Collections.singletonList("dbRole");
        when(systemDb.executeTransactionally(anyString(), anyMap(), any())).thenReturn(dbRoles);

        AuthInfo authInfo = samlPlugin.authenticateAndAuthorize(authToken);

        verify(authToken).principal();
        verify(authToken).credentials();
        verify(httpClient).execute(any(HttpGet.class), any(HttpClientContext.class));
        verify(systemDb).executeTransactionally(anyString(), anyMap(), any());

        assertNotNull(authInfo);
        assertEquals("testUser", authInfo.principal());
        assertTrue(authInfo.roles().contains("testRole"));
        assertTrue(authInfo.roles().contains("dbRole"));
    }

    @Test
    public void testHandleHttpResponse() {
        when(httpResponse.getStatusLine()).thenReturn(mock(org.apache.http.StatusLine.class));
        when(httpResponse.getStatusLine().getStatusCode()).thenReturn(HttpStatus.SC_OK);

        when(systemDb.beginTx()).thenReturn(transaction);
        when(transaction.execute(anyString(), anyMap())).thenReturn(result);
        when(result.hasNext()).thenReturn(true);
        when(result.next()).thenReturn(Collections.singletonMap("roles", Collections.singletonList("testRole")));

        verify(authProviderOperations.log()).info(contains("ECB SAML plugin initialized."));
    }

    @Test(expected = AuthenticationException.class)
    public void testHandleHttpResponseUnauthorized() throws Exception {
        when(httpResponse.getStatusLine()).thenReturn(mock(org.apache.http.StatusLine.class));
        when(httpResponse.getStatusLine().getStatusCode()).thenReturn(HttpStatus.SC_SEE_OTHER);

        samlPlugin.handleHttpResponse(httpResponse, "testUser");
    }

    @Test
    public void testLoadConfig() throws Exception {
        Properties properties = new Properties();
        properties.setProperty("plugins.auth.saml.validation_url", "https://example.com/validate");
        properties.setProperty("plugins.auth.saml.default_role", "defaultRole");

        doReturn(properties).when(samlPlugin).loadProperties(any());

        samlPlugin.loadConfig();

        assertEquals(new URI("https://example.com/validate"), samlPlugin.validationUri);
        assertEquals("defaultRole", samlPlugin.defaultRole);
    }

    @Test
    public void testStart() {
        when(dbms.database(GraphDatabaseSettings.SYSTEM_DATABASE_NAME)).thenReturn(systemDb);
        ExposeConfigExtensionFactory.setDbms(dbms);

        samlPlugin.start();

        assertNotNull(samlPlugin.systemDb);
        assertNotNull(samlPlugin.httpClient);
    }

    @Test
    public void testLoadPropertiesSuccess() throws IOException {
        Path mockPath = mock(Path.class);
        InputStream mockInputStream = new ByteArrayInputStream("plugins.auth.saml.validation_url=https://example.com/validate\nplugins.auth.saml.default_role=defaultRole".getBytes());

        doReturn(mockInputStream).when(samlPlugin).getInputStream(mockPath);

        Properties loadedProperties = samlPlugin.loadProperties(mockPath);

        assertNotNull(loadedProperties);
        assertEquals("https://example.com/validate", loadedProperties.getProperty("plugins.auth.saml.validation_url"));
        assertEquals("defaultRole", loadedProperties.getProperty("plugins.auth.saml.default_role"));
    }

    @Test
    public void testFindRolesInSystemDbFor() {
        String principal = "testUser";

        when(systemDb.executeTransactionally(anyString(), anyMap(), any())).thenAnswer(invocation -> {
            Map<String, Object> params = (Map<String, Object>) invocation.getArguments()[1];
            if (params.get("user").equals(principal)) {
                return Collections.singletonList("testRole");
            }
            return Collections.emptyList();
        });

        List<String> roles = samlPlugin.findRolesInSystemDbFor(principal);

        assertNotNull(roles);
        assertTrue(roles.contains("testRole"));

        verify(systemDb).executeTransactionally(anyString(), anyMap(), any());
    }

    @Test
    public void testFindRolesInSystemDbForNoRoles() {
        String principal = "testUser";

        when(systemDb.executeTransactionally(anyString(), anyMap(), any())).thenAnswer(invocation -> {
            Result mockResult = mock(Result.class);
            when(mockResult.hasNext()).thenReturn(false);
            return Collections.emptyList();
        });

        List<String> roles = samlPlugin.findRolesInSystemDbFor(principal);

        assertNotNull(roles);
        assertTrue(roles.isEmpty());

        verify(systemDb).executeTransactionally(anyString(), anyMap(), any());
    }

    @Test
    public void testFindRolesInSystemDbForNullMap() {
        String principal = "testUser";

        when(systemDb.executeTransactionally(anyString(), anyMap(), any())).thenAnswer(invocation -> {
            Result mockResult = mock(Result.class);
            when(mockResult.hasNext()).thenReturn(true).thenReturn(false);
            when(mockResult.next()).thenReturn(null);
            return Collections.emptyList();
        });

        List<String> roles = samlPlugin.findRolesInSystemDbFor(principal);

        assertNotNull(roles);
        assertTrue(roles.isEmpty());

        verify(systemDb).executeTransactionally(anyString(), anyMap(), any());
    }

    @Test
    public void testFindRolesInSystemDbForWithRoles() {
        String principal = "testUser";
        List<String> expectedRoles = Arrays.asList("role1", "role2");

        when(systemDb.executeTransactionally(anyString(), anyMap(), any())).thenAnswer(invocation -> {
            Result mockResult = mock(Result.class);
            when(mockResult.hasNext()).thenReturn(true).thenReturn(false);
            Map<String, Object> resultMap = new HashMap<>();
            resultMap.put(ROLE_CLAIM, expectedRoles);
            when(mockResult.next()).thenReturn(resultMap);
            return expectedRoles;
        });

        List<String> roles = samlPlugin.findRolesInSystemDbFor(principal);

        assertNotNull(roles);
        assertEquals(expectedRoles, roles);

        verify(systemDb).executeTransactionally(anyString(), anyMap(), any());
    }

    @Test
    public void testExtractRolesWithEmptyRolesAndDefaultRole() throws AuthenticationException {
        String username = "testUser";
        String defaultRole = "defaultTestRole";
        samlPlugin.defaultRole = defaultRole;

        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.createObjectNode();
        ((ObjectNode) jsonNode).putArray(ROLE_CLAIM);

        doReturn(Collections.emptyList()).when(samlPlugin).findRolesInSystemDbFor(username);

        List<String> roles = samlPlugin.extractRoles(jsonNode, username);

        assertNotNull(roles);
        assertEquals(1, roles.size());
        assertTrue(roles.contains(defaultRole));

        verify(log).debug("Extracted roles from JSON: []");
        verify(log).debug("Roles found in database: []");
        verify(log).debug("Final roles for user testUser: [defaultTestRole]");
    }
}