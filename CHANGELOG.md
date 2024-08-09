# Changelog

All notable changes to this project will be documented in this file. A new version will be created once publishing the package. The related
commit will automatically be tagged with the version of the package.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2024-06-20

### Changed

- Small maintainability fixes based on sonarqube reports

## [1.1.0] - 2024-04-15

### Changed

- Calculate SonarQube diff against main
- Upgraded to neo4j version `5.15`

### Deleted

- Debug logging for the HTTP request to backend

## [1.0.9] - 2024-01-19

### Added

- Debug logging for the HTTP request to backend

## [1.0.8] - 2023-09-27

- Bugfix: Added back `_` substitution that was mistakenly removed in the last version

## [1.0.7] - 2023-09-22

### Changed

- Remove additional nginx and switch to navi-app-backend for SAML integration

## [1.0.6] - 2023-08-28

### Changed

- Substitute `-` with `__` in entitlements because Neo4j roles can only be alphanumeric and underscores

## [1.0.5] - 2023-08-15

### Deleted

- Debug logging

## [1.0.4] - 2023-08-15

### Changed

- Only process needed cookies to avoid problems with AWS cookies set by kuberentes ingress

## [1.0.3] - 2023-08-15

### Added

- Debug logging

## [1.0.2] - 2023-08-15

### Added

- Debug logging

## [1.0.1] - 2023-06-27

### Changed

- Fixed CI/CD

## [1.0.0] - 2023-06-23

### Added

- Initial plugin version