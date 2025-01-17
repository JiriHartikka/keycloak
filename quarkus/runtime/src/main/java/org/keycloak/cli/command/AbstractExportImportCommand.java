/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.cli.command;

import static org.keycloak.cli.Picocli.error;

import org.keycloak.util.Environment;

import picocli.CommandLine;

public abstract class AbstractExportImportCommand extends AbstractCommand implements Runnable {

    private final String action;

    @CommandLine.Option(names = "--dir", arity = "1", description = "Set the path to a directory where files will be created with the exported data.", paramLabel = "<path>") String toDir;
    @CommandLine.Option(names = "--file", arity = "1", description = "Set the path to a file that will be created with the exported data.", paramLabel = "<path>") String toFile;
    @CommandLine.Option(names = "--realm", arity = "1", description = "Set the name of the realm to export", paramLabel = "<realm>") String realm;

    protected AbstractExportImportCommand(String action) {
        this.action = action;
    }

    @Override
    public void run() {
        doBeforeRun();
        System.setProperty("keycloak.migration.action", action);

        if (toDir != null) {
            System.setProperty("keycloak.migration.provider", "dir");
            System.setProperty("keycloak.migration.dir", toDir);
        } else if (toFile != null) {
            System.setProperty("keycloak.migration.provider", "singleFile");
            System.setProperty("keycloak.migration.file", toFile);
        } else {
            error(spec.commandLine(), "Must specify either --dir or --file options.");
        }

        if (realm != null) {
            System.setProperty("keycloak.migration.realmName", realm);
        }

        Environment.setProfile(Environment.IMPORT_EXPORT_MODE);

        new CommandLine(new Main()).execute("start");
    }

    protected void doBeforeRun() {

    }
}
