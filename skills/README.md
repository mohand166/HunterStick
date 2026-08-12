# Skill library

Choose the category that matches the objective, then invoke the skill by its slug. The directory
is for human navigation; invocation names do not include the category. For example, ask for
`subdomain-enumeration`, not `know-your-target/subdomain-enumeration`.

| Category | Use it for |
|---|---|
| [`setup/`](setup/) | Create a target brain before any work starts. |
| [`know-your-target/`](know-your-target/) | Establish ownership, names, DNS, reachable hosts, ports, and web services. |
| [`surface-discovery/`](surface-discovery/) | Find technologies, components, URLs, content, JavaScript, APIs, and parameters. |
| [`application-understanding/`](application-understanding/) | Understand authentication and application behavior. |
| [`external-assets/`](external-assets/) | Examine cloud assets, repositories, secrets, and takeover candidates. |
| [`context-and-prioritization/`](context-and-prioritization/) | Correlate evidence, derive properties, rank surface, and prepare handoff. |
| [`monitoring/`](monitoring/) | Detect subdomain, HTTP, technology, and JavaScript changes. |
| [`analysis/`](analysis/) | Analyze a supplied HTTP request or named technology without testing. |
| [`vulnerability-testing/`](vulnerability-testing/) | Route a user-selected vulnerability objective into the class hunting loop. |
| [`orchestration/`](orchestration/) | Run an approved situation flow or compose a multi-step objective. |
| [`maintenance/`](maintenance/) | Re-evaluate one skill or playbook from build-time knowledge. |

[`shared/_recon-method.md`](shared/_recon-method.md) is loaded with recon objectives. It is shared
method, not an invocable skill. `tools/preflight.py <target> --list` prints all 32 invocable slugs,
grouped by these categories, and reports which required inputs exist.
