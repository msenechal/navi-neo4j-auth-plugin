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

import org.neo4j.annotations.service.ServiceProvider;
import org.neo4j.dbms.api.DatabaseManagementService;
import org.neo4j.kernel.extension.ExtensionFactory;
import org.neo4j.kernel.extension.ExtensionType;
import org.neo4j.kernel.extension.context.ExtensionContext;
import org.neo4j.kernel.lifecycle.Lifecycle;
import org.neo4j.kernel.lifecycle.LifecycleAdapter;

@ServiceProvider
public class ExposeConfigExtensionFactory extends ExtensionFactory<ExposeConfigExtensionFactory.Dependencies> {

    public ExposeConfigExtensionFactory() {
        super(ExtensionType.GLOBAL, "exposeConfig");
    }

    private static DatabaseManagementService dbms = null;

    public static DatabaseManagementService getDbms() {
        return dbms;
    }

    public static void setDbms(DatabaseManagementService db) {
        dbms = db;
    }

    @Override
    public Lifecycle newInstance(ExtensionContext context, Dependencies dependencies) {
        return new LifecycleAdapter() {
            @Override
            public void init() {
                setDbmsInternal(dependencies.databaseManagementService());
            }
        };
    }

    private static void setDbmsInternal(DatabaseManagementService db) {
        dbms = db;
    }

    public interface Dependencies {
        DatabaseManagementService databaseManagementService();
    }
}
