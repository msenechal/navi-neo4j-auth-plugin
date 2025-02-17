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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.neo4j.dbms.api.DatabaseManagementService;
import org.neo4j.kernel.extension.context.ExtensionContext;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ExposeConfigExtensionFactoryTest {

    private ExposeConfigExtensionFactory exposeConfigExtensionFactory;
    private static DatabaseManagementService dbms;

    @BeforeEach
    public void setUp() {
        exposeConfigExtensionFactory = new ExposeConfigExtensionFactory();
        dbms = mock(DatabaseManagementService.class);
    }

    @Test
    void testSetAndGetDbms() {
        ExposeConfigExtensionFactory.setDbms(dbms);
        assertEquals(dbms, ExposeConfigExtensionFactory.getDbms());
    }

    @Test
    void testNewInstance() throws Exception {
        ExposeConfigExtensionFactory.Dependencies dependencies = mock(ExposeConfigExtensionFactory.Dependencies.class);
        when(dependencies.databaseManagementService()).thenReturn(dbms);

        ExtensionContext context = mock(ExtensionContext.class);

        exposeConfigExtensionFactory.newInstance(context, dependencies).init();

        assertEquals(dbms, ExposeConfigExtensionFactory.getDbms());
    }
}