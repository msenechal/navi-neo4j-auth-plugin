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

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonNode;
import com.neo4j.server.security.enterprise.auth.plugin.api.AuthProviderOperations;
import com.neo4j.server.security.enterprise.auth.plugin.api.AuthenticationException;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.neo4j.graphdb.GraphDatabaseService;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Properties;

import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.*;

public class SamlPluginExceptionTest {

    private SamlPlugin samlPlugin;

    @Mock
    private CloseableHttpResponse httpResponse;

    @Mock
    private StatusLine statusLine;

    @Mock
    private AuthProviderOperations authProviderOperations;

    @Mock
    private AuthProviderOperations.Log log;

    @Mock
    private GraphDatabaseService systemDb;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        samlPlugin = spy(new SamlPlugin());
        samlPlugin.api = authProviderOperations;
        when(authProviderOperations.log()).thenReturn(log);
    }

    @Test(expected = AuthenticationException.class)
    public void testHandleHttpResponseUnauthorized() throws Exception {
        when(statusLine.getStatusCode()).thenReturn(HttpStatus.SC_SEE_OTHER);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);

        samlPlugin.handleHttpResponse(httpResponse, "testUser");
    }

    @Test(expected = AuthenticationException.class)
    public void testHandleHttpResponseUnexpectedStatus() throws Exception {
        when(statusLine.getStatusCode()).thenReturn(HttpStatus.SC_BAD_REQUEST);
        when(statusLine.toString()).thenReturn("400 Bad Request");
        when(httpResponse.getStatusLine()).thenReturn(statusLine);

        samlPlugin.handleHttpResponse(httpResponse, "testUser");
    }

    @Test(expected = JsonParseException.class)
    public void testHandleSuccessResponseInvalidJson() throws Exception {
        String invalidJson = "invalid json";
        mockHttpEntity(invalidJson);

        samlPlugin.handleSuccessResponse(httpResponse, "testUser");
    }

    @Test(expected = AuthenticationException.class)
    public void testHandleSuccessResponseNullJsonNode() throws Exception {
        JsonNode nullJsonNode = null;
        samlPlugin.extractRoles(nullJsonNode, "testUser");
    }

    @Test
    public void testLoadPropertiesIOException() throws IOException {
        Path mockPath = mock(Path.class);
        doThrow(new IOException("File not found")).when(samlPlugin).getInputStream(mockPath);

        Properties loadedProperties = samlPlugin.loadProperties(mockPath);

        assertNotNull(loadedProperties);
        verify(log).error(contains("Failed to load config file"));
    }

    private void mockHttpEntity(String content) throws IOException {
        HttpEntity httpEntity = mock(HttpEntity.class);
        when(httpEntity.getContent()).thenReturn(new java.io.ByteArrayInputStream(content.getBytes()));
        when(httpResponse.getEntity()).thenReturn(httpEntity);
    }
}