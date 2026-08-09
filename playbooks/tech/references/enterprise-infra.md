# Enterprise application and infrastructure lens

Load this for administrative products, developer platforms, Java application servers and exposed
network/security appliances. These products are version-sensitive and high impact; passive or
minimal verification and exact ownership matter.

## Start with product role and ownership

| role | products covered | primary trust boundaries |
|---|---|---|
| CI/CD and source | Jenkins, GitLab | anonymous/authenticated API, projects/jobs, runners/agents, webhooks, artifacts, credentials, plugins |
| collaboration | Jira, Confluence, SharePoint | tenant/site/project/space permissions, attachments, macros/apps, search/export, SSO |
| mail/groupware | Exchange/OWA, Zimbra | auth/SSO, mailbox/tenant boundaries, autodiscover, attachments, admin endpoints |
| observability/data/admin | Grafana, Kibana/Elastic, SonarQube, Jupyter | organization/space/project permissions, data sources, saved objects, notebooks/jobs, plugins and credentials |
| orchestration/developer ops | Kubernetes dashboards, Argo CD, Airflow, Nexus/Artifactory, Harbor | namespaces/projects, repositories/artifacts, jobs/workflows, service accounts/tokens, webhooks and admin APIs |
| Java platform | Tomcat, Jetty, WebLogic, WildFly/JBoss | deployed apps versus management console, connectors, realms, JMX, exact patch line |
| virtualization/admin | vCenter | SSO, inventory permissions, plugins, API/UI clients, management-plane exposure |
| edge appliance | Citrix NetScaler, Fortinet, Ivanti | management versus user gateway, exact firmware/build, cluster nodes, vendor mitigations |
| web server/proxy | nginx, Apache HTTP Server, IIS, Caddy | virtual hosts, aliases/static roots, modules, proxy normalization, auth offload, version claim |

Determine whether the program owns a SaaS tenant, self-hosted installation, managed appliance or
only an application behind it. Vendor infrastructure may be explicitly out of scope.

## Product-specific directions

### Jenkins

- Inventory core **and plugins**; plugin versions and reachability are often more actionable than
  core.
- Map anonymous/read/build/configure/script/admin permissions, job parameters, SCM/webhooks,
  artifacts and agent/controller boundaries.
- Treat login, API metadata and a plugin's presence as facts, not findings.
- Never execute builds, scripts or state-changing administrative actions without explicit
  authorization.

### GitLab

- Establish edition/deployment/version and feature exposure: projects/groups, repository/archive,
  CI pipelines/runners, registry/packages, imports, webhooks/integrations and GraphQL/REST.
- Compare membership and token scopes across group/project/inherited resources.
- Hosted GitLab.com and a target's self-managed GitLab have different ownership boundaries.

### Jira/Confluence/SharePoint

- Model global, tenant/site, project/space and object-level permissions separately.
- Identify marketplace apps/macros/connectors and their own routes/versioning.
- Search, export, attachments, previews and historical versions may apply different filters from the
  normal page.
- Do not equate public issue/page metadata with a vulnerability without program policy and impact.

### Java application servers

- Separate container/server version from the deployed application's Spring/Struts/JSF version.
- Identify management connectors/consoles and their bind host/port independently from application
  routes.
- Version banners are frequently suppressed, customized or emitted by a proxy; seek build/error or
  package evidence before advisory matching.

### Appliances

- Require exact product, build/firmware and deployment role before advisory research.
- Prefer vendor-supported passive version sources and non-state-changing health/login behavior.
- Never validate denial-of-service, memory corruption, command execution or authentication bypass
  against an appliance merely because a scanner reports an affected version.
- Note active exploitation/required mitigation from official vendor and CISA sources for triage,
  but a version match remains a hypothesis.

### Web servers and reverse proxies

- Treat the server as one hop, not the application framework.
- Map virtual-host selection, aliases/static roots, internal redirects, path normalization,
  forwarding headers, method/body handling and cache behavior.
- A banner is `reported`; a behavior plus configuration artifact may establish more.

## Hypothesis transforms

| observed surface | canonical classes |
|---|---|
| project/job/space/object access varies incorrectly by role/tenant | `idor-bola`, `function-level-authorization`, `multi-tenant-isolation` |
| import/webhook/proxy/preview accepts destination | `ssrf` |
| artifact/attachment/archive/media path crosses storage boundary | `file-upload`, `path-traversal`, possibly `xxe`/`deserialization` with parser evidence |
| plugin/module is pinned to affected release and reachable | target-specific hypothesis → `research-component`; class comes from the advisory invariant |
| auth offload or forwarded identity differs across hops | `authentication-bypass`, `privilege-escalation`, `host-header-attacks` |
| edge expected to protect directly reachable origin | `origin-exposure` |
| proxy/application parser or normalization differs | `request-smuggling` or access-control class only after the prerequisite evidence exists |

## Current official sources

- Jenkins advisories (core and plugins): <https://www.jenkins.io/security/advisories/>
- GitLab releases/security: <https://about.gitlab.com/releases/categories/releases/>
- Atlassian security advisories: <https://www.atlassian.com/trust/security/advisories>
- Microsoft Security Response Center: <https://msrc.microsoft.com/update-guide/>
- Oracle Critical Patch Updates: <https://www.oracle.com/security-alerts/>
- VMware/Broadcom security advisories: <https://support.broadcom.com/web/ecx/security-advisory>
- CISA Known Exploited Vulnerabilities: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- nginx advisories: <https://nginx.org/en/security_advisories.html>
- Apache HTTP Server vulnerabilities: <https://httpd.apache.org/security/vulnerabilities_24.html>

Search the vendor's current advisory and release pages at analysis time. Use
[`live-research.md`](live-research.md); never preserve an appliance CVE list here.
