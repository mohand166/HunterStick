# Spring Boot

> A Spring Boot application may include a separately configured management plane and several
> independent security/filter chains. Actuator availability, web exposure, sanitization, port/base
> path and authorization vary by release and target configuration.

## 1 · Identity and deployment modes

Record MVC versus WebFlux, servlet container, Spring Security presence, application versus
management port/address, gateway/proxy, packaging mode and relevant starters/components. Separate
Spring Boot, Spring Framework, Spring Security, container and third-party parser versions.

## 2 · Fingerprint and disambiguation

- **Confirms:** an Actuator links response or version-bearing Spring Boot artifact.
- **Corroborates:** Spring Boot error-page/JSON conventions and older framework-specific headers.
- **Suggests only:** `JSESSIONID`, Java error syntax, Swagger UI or a scanner's `Spring` label.
- **Negative case:** a Java servlet application or Spring Framework app is not necessarily Spring
  Boot, and an edge-generated error does not fingerprint the origin.

## 3 · Version and component identity

Build metadata, dependency manifests/SBOMs and version-bearing artifacts are stronger than banners.
Actuator `info` is configuration-dependent; environment/config endpoints show properties, not a
complete dependency tree, and values may be sanitized. Record each relevant Maven/Gradle
`groupId:artifactId` and container separately as `exact`, `bounded` or `unknown`.

## 4 · Native surface

| observed mechanism | what it changes |
|---|---|
| Actuator discovery and management endpoints | a separately exposed/authorized operational plane may exist |
| configurable management port/address/base path | absence on the application path says little about another intended listener |
| servlet filters / WebFlux filter chain / method security | different entrypoints may receive different authorization controls |
| MVC path matching, matrix variables and proxy normalization | edge, security matcher and controller may interpret a path differently |
| controller/model binding and validation | request fields can become objects before policy/business checks |
| Jackson/XML/YAML/template components | parser and expression risk depends on exact package, configuration and reachable sink |
| error handling and OpenAPI/springdoc | route/schema/error evidence may reveal entrypoints without itself being impact |

Treat writable management operations, heap dumps, shutdown and large diagnostic artifacts as
state-changing/sensitive. Do not invoke or download them without explicit authorization.

## 5 · Security controls and trust boundaries

Build the hop chain: edge → container → filter/security chain → dispatcher/controller → service.
For management and application endpoints independently record bind address/port, exposure include/
exclude configuration, authentication/authorization and value sanitization. Determine whether
method-level security supplements or replaces path rules. Trace parser, template and data-binding
hypotheses to a named reachable component rather than from “Java” alone.

## 6 · Target-specific hypothesis transforms

| observed feature | boundary and oracle | canonical class |
|---|---|---|
| edge/security matcher/controller disagree on normalized path | protected control route versus minimally varied route under same principal | `function-level-authorization` |
| application and management chains apply different identity/policy | same safe read-only capability through each intended listener/path | `function-level-authorization`, `authentication-bypass` |
| automatic binding accepts fields beyond the operation contract | allowed control field versus harmless protected field | `mass-assignment`, `privilege-escalation` |
| exact parser/deserializer receives attacker-controlled content | benign positive/negative type or parser oracle | `deserialization`, `xxe` or matching parser class |
| user input reaches SpEL/template evaluation API | safe expression versus literal control at the evidenced sink | `template-injection` |
| management data crosses an unintended audience | identify the missing function/object/tenant/cache control before assigning a class | applicable canonical access-control/cache class or unclassified hypothesis |
| proxy and app disagree on trusted host/scheme/forwarded identity | paired requests that alter only the trusted signal | `host-header-attacks`, `authentication-bypass` or applicable class |

## 7 · Lower-priority paths

- Current limited Actuator defaults lower broad management enumeration only after release/config
  evidence; observed links/listeners override remembered defaults.
- Packaged JAR deployment lowers writable-webroot assumptions, not application file import/read.
- Parameterized repository/ORM use lowers SQL injection only for the observed query sink.
- Escaped server templates lower XSS only until raw rendering or another output context appears.

## 8 · Live research entrypoints

- Spring Boot Actuator endpoint behavior: <https://docs.spring.io/spring-boot/reference/actuator/endpoints.html>
- Spring security advisories: <https://spring.io/security>
- Spring Security reference: <https://docs.spring.io/spring-security/reference/>
- Spring Boot supported versions/releases: <https://spring.io/projects/spring-boot#support>

Use [`references/live-research.md`](references/live-research.md) for changed defaults, supported
lines and exact component advisories; use component-inventory for the actual dependency inventory.

## 9 · Noise, ownership and stop conditions

Health `UP`, a Whitelabel/error page, a route map or a version claim is not automatically a
finding. Echo of a supplied path is reflection, not XSS without a rendering context. Stop when the
management surface is not in scope, only DoS impact applies, or product/version/reachable feature
cannot be established. Preserve proxy-versus-origin fingerprint conflicts as architecture evidence.
