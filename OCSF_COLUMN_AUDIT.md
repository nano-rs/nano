# OCSF 1.8.0 Column Audit — Promoted ClickHouse Columns

Audit of every column promoted out of the OCSF `event` JSON in `clickhouse/ocsf/init.sql`
(driven by `nanosiem-core/docs/ocsf/1.8.0/udm_ocsf_mapping.json`), verified attribute-by-attribute
against the **live OCSF 1.8.0 schema server** (`https://schema.ocsf.io/api/1.8.0/...`, fully-resolved
JSON) as the authoritative source, cross-checked with the local partial bundle.

Two verdicts per column:
- **PATH-VALID / PATH-INVALID** — does the dotted path resolve through real OCSF 1.8.0
  attributes/objects with a compatible type?
- **MAPPING-OK / MAPPING-WRONG** — does the UDM field map to the semantically correct OCSF home?

Legend for requirement: req=required / rec=recommended / opt=optional (OCSF `requirement`).

---

## TAXONOMY / CORE (base_event)

All confirmed present on `base_event` (verified on process_activity which inherits base).

| column | path-valid | mapping-ok | correct path if wrong | citation |
|---|---|---|---|---|
| `class_uid` | VALID | OK | — | base_event.class_uid req=required, integer_t |
| `category_uid` | VALID | OK | — | base_event.category_uid req=required, integer_t |
| `activity_id` | VALID | OK | — | base_event.activity_id req=required, integer_t |
| `activity` (←activity_name) | VALID* | OK | — | `activity_name` is the server-resolved sibling enum string of activity_id; emitters serialize it. Column name `activity` is a nano-internal label. *Not a base attribute literally named `activity`; it's the resolved `activity_name`. Acceptable. |
| `type_uid` | VALID | OK | — | base_event.type_uid req=required, long_t → UInt64 |
| `severity_id` | VALID | OK | — | base_event.severity_id req=required, integer_t |
| `severity` | VALID | OK | — | base_event.severity req=optional, string_t |
| `status_id` | VALID | OK | — | base_event.status_id (on auth req=recommended), integer_t |
| `status` | VALID | OK | — | base_event.status string_t |
| `message` | VALID | OK | — | base_event.message req=recommended, string_t |
| `time_dt`/`timestamp` (←time) | VALID | OK | — | base_event.time req=required, timestamp_t (epoch ms) |
| `metadata.uid` (id) | VALID | OK | — | metadata.uid req=**optional**, string_t — "unique identifier assigned to the OCSF event... specific to the OCSF event itself" = producer event id. **Special #6 CONFIRMED**: it is the producer event id string, and because it is OPTIONAL the CH row id is correctly server-owned (UUIDv7), not metadata.uid. |

---

## NETWORK

Applies to network_activity (4001): has `src_endpoint`, `dst_endpoint` (network_endpoint),
`connection_info` (network_connection_info), `traffic` (network_traffic), `url` (url), `device`.

| column | path-valid | mapping-ok | correct path if wrong | citation |
|---|---|---|---|---|
| `src_endpoint.ip` | VALID | OK | — | network_endpoint.ip rec, ip_t. class attr `src_endpoint`="initiator of the network connection" |
| `dst_endpoint.ip` | VALID | OK | — | network_endpoint.ip; `dst_endpoint`="responder" |
| `src_endpoint.port` | VALID | OK | — | network_endpoint.port rec, port_t → UInt16 |
| `dst_endpoint.port` | VALID | OK | — | network_endpoint.port |
| `src_endpoint.mac` | VALID | OK | — | network_endpoint.mac opt, mac_t |
| `dst_endpoint.mac` | VALID | OK | — | network_endpoint.mac |
| `src_endpoint.hostname` | VALID | OK | — | network_endpoint.hostname rec, hostname_t |
| `device.hostname` | VALID | OK | — | device.hostname rec, hostname_t. Correct fallback for endpoint-centric classes (process_activity has `device` req=required, no src_endpoint). |
| `dst_endpoint.hostname` | VALID | OK | — | network_endpoint.hostname |
| `connection_info.protocol_num` | VALID | OK | — | **Special #3 CONFIRMED**: class attribute is literally named `connection_info` (object_type=network_connection_info; NOT `network_connection_info` as the attr name). `protocol_num` rec, integer_t. |
| `traffic.bytes_in` | VALID | OK⚠ | — | network_traffic.bytes_in opt, long_t → UInt64. ⚠ **Direction caveat**: OCSF bytes_in = "bytes sent from the destination to the source (inbound)". If UDM bytes_in means "received by host" the names align; if UDM uses a different convention there is a semantic mismatch. Path/name are exact; verify direction semantics. |
| `traffic.bytes_out` | VALID | OK⚠ | — | network_traffic.bytes_out opt — "source to destination (outbound)". Same direction caveat. |
| `traffic.packets_in` | VALID | OK⚠ | — | network_traffic.packets_in opt, long_t. Same direction caveat. |
| `traffic.packets_out` | VALID | OK⚠ | — | network_traffic.packets_out opt, long_t. Same direction caveat. |

---

## IDENTITY

`user` (req=required on authentication) = the subject being authenticated.
`actor.user` (rec) = the user that initiated the activity.

| column | path-valid | mapping-ok | correct path if wrong | citation |
|---|---|---|---|---|
| `user.name` (user) | VALID | OK | — | user.name rec, username_t. On auth 3002 `user` req=required = "The subject (user/role or account) to authenticate." Correct subject. |
| `actor.user.name` (src_user) | VALID | OK | — | actor.user rec = "user that initiated the activity"; user.name. Correct initiator. |
| `user.domain` | VALID | OK | — | user.domain opt, string_t |
| `user.uid` | VALID | OK | — | user.uid rec, string_t = "unique user identifier... Windows SID, AD DN or AWS uid" (opaque string — String storage correct) |

---

## PROCESS — ⚠ PRIMARY MAPPING IS INVERTED (Special #1)

**process_activity (1007) requirements (CONFIRMED from live server):**
- `process` **req=required**, object_t process = *"The process that was launched, injected into, opened, or terminated."* → this is the **SUBJECT/target** process.
- `actor` **req=required**; `actor.process` (rec) = *"The process that initiated the activity"* → this is the **PARENT/initiator** process.

UDM `process_name`/`command_line`/`process_id`/`process_hash` denote the **primary process — "what ran"** — which in OCSF is the top-level **`process`**, NOT `actor.process`.
The manifest designates `actor.process.*` as the **primary/default** promotion ("UDM process_name resolves to actor's by default") and `process.*` as secondary. **This is backwards for process_activity.**

| column | path-valid | mapping-ok | correct path if wrong | citation |
|---|---|---|---|---|
| `actor.process.name` (process_name, **primary**) | VALID | **WRONG** | `process.name` should be the primary for 1007 | process.name rec, process_name_t. process=subject; actor.process="initiated the activity"=parent |
| `process.name` (process_name, secondary) | VALID | OK (but should be PRIMARY) | promote to primary | same |
| `actor.process.cmd_line` (command_line, **primary**) | VALID | **WRONG** | `process.cmd_line` primary for 1007 | process.cmd_line rec, string_t |
| `process.cmd_line` (command_line, secondary) | VALID | OK (should be PRIMARY) | promote to primary | same |
| `actor.process.parent_process.cmd_line` (parent_command_line) | VALID | OK✅ | — | actor.process.parent_process (process) → cmd_line. **HOWEVER** see note: the true *grandparent*. UDM parent_command_line = parent of the primary process = the **`process.parent_process.cmd_line`** OR `actor.process.cmd_line` (the initiator IS the parent). Mapping it to `actor.process.parent_process.cmd_line` makes it the grandparent. **MAPPING-WRONG for 1007**: correct = `process.parent_process.cmd_line` (parent of subject) — or, since actor.process is itself the parent, `actor.process.cmd_line`. |
| `actor.process.pid` (process_id, primary) | VALID | **WRONG** | `process.pid` primary for 1007 | process.pid rec, integer_t |
| `actor.process.uid` (process_guid, primary) | VALID | **WRONG** | `process.uid` primary for 1007 | process.uid rec, string_t = "unique identifier for this process assigned by the producer" |
| `actor.process.file.hashes[3].value` (process_hash) | VALID | **WRONG (primary)** | `process.file.hashes[3].value` primary for 1007 | actor→process→file(rec)→hashes(fingerprint[],rec); fingerprint.value req, algorithm_id=3=SHA-256 (CONFIRMED). Path resolves but points at the initiator's binary, not the launched binary. |

**Correct PROCESS mapping for process_activity 1007:**
- process_name → **`process.name`** (subject) ; actor.process.name = parent (secondary)
- command_line → **`process.cmd_line`** ; actor.process.cmd_line = parent cmd (secondary)
- process_id → **`process.pid`**
- process_guid → **`process.uid`**
- process_hash → **`process.file.hashes[].value`** (algorithm_id=3)
- parent_command_line → **`process.parent_process.cmd_line`** (parent of subject) *or* `actor.process.cmd_line` (initiator==parent). **NOT** `actor.process.parent_process.cmd_line` (that's the grandparent).

Note: for classes where the relevant process IS the actor (e.g. network/auth context where only an initiating process exists), `actor.process.*` is right. The fix is to make `process.*` the **default/primary** for the System-category classes (1007/1001) and COALESCE, not to keep `actor.process.*` as the default.

---

## FILE

file_activity (1001): `file` (target) and `actor` present.

| column | path-valid | mapping-ok | correct path if wrong | citation |
|---|---|---|---|---|
| `file.name` | VALID | OK | — | file.name req=required, file_name_t |
| `file.path` | VALID | OK | — | file.path rec, file_path_t |
| `file.hashes[3].value` (file_hash) | VALID | OK | — | file.hashes fingerprint[] rec; fingerprint.value req; algorithm_id=3=SHA-256 CONFIRMED. No scalar file_hash exists in OCSF — array-flatten is correct. |
| `activity_id` (file_action) | VALID | OK | — | file action encoded in activity_id enum (Create=1…Delete=4…). Reuse of taxonomy column, documented. |

---

## AUTH (authentication 3002) — Special #5 CONFIRMED

| column | path-valid | mapping-ok | correct path if wrong | citation |
|---|---|---|---|---|
| `auth_protocol_id` (auth_type) | VALID | OK | — | authentication.auth_protocol_id rec, integer_t (class-level attr, CONFIRMED) |
| `auth_protocol` (auth_type) | VALID | OK | — | authentication.auth_protocol rec, string_t sibling |
| `status_id` (auth_result) | VALID | OK | — | status_id rec (base/auth) = normalized event status (Success/Failure). Correct home for auth outcome. |
| `session.uid` (session_id) | VALID | OK | — | session.uid rec, string_t |
| `is_mfa` (mfa_used) | VALID | OK | — | authentication.is_mfa rec, boolean_t → UInt8 (CONFIRMED) |

---

## WEB / HTTP — ⚠ TOP-LEVEL `url` IS INVALID ON HTTP ACTIVITY (Special #2)

**http_activity (4002) CONFIRMED: NO top-level `url` attribute.** It has `http_request` (rec, object_t http_request) and `http_response` (rec). The URL lives at **`http_request.url`** (http_request.url rec, object_t url).

`url.hostname` and `url.url_string` use a **top-level `url`** which does NOT exist on 4002.
- On **network_activity (4001)** top-level `url` DOES exist (rec) → valid there.
- On **dns_activity** there is NO top-level `url`.

| column | path-valid | mapping-ok | correct path if wrong | citation |
|---|---|---|---|---|
| `url.hostname` (url_domain) | VALID on 4001 / **INVALID on 4002** | OK on 4001 | for HTTP: `http_request.url.hostname` | network_activity.url rec (url obj); url.hostname rec. http_activity has NO top-level url. |
| `url.url_string` (url) | VALID on 4001 / **INVALID on 4002** | OK on 4001 | for HTTP: `http_request.url.url_string` | url.url_string rec, url_t. (manifest correctly notes `text` is NOT a 1.8.0 url attr — confirmed, url has only hostname/path/url_string among these.) |
| `http_request.http_method` (http_method) | VALID | OK | — | http_request.http_method rec, string_t |
| `http_request.url.path` (url) | VALID | OK | — | http_request.url (url) → path rec, string_t |
| `http_request.user_agent` (http_user_agent) | VALID | OK | — | http_request.user_agent rec, string_t |
| `http_response.code` (http_status_code) | VALID | OK | — | http_response.code **req=required**, integer_t → UInt16 |

**Fix:** add HTTP-class URL columns `http_request.url.hostname` and `http_request.url.url_string` (the top-level `url.*` columns only populate for network_activity 4001; HTTP rows leave them empty). The single `http_request.url.path` already promoted is insufficient for url_domain/full-url on HTTP.

---

## DNS (dns_activity 4003) — Special #4 CONFIRMED

| column | path-valid | mapping-ok | correct path if wrong | citation |
|---|---|---|---|---|
| `query.hostname` (query) | VALID | OK | — | dns_activity.query (dns_query) rec; dns_query.hostname **req=required**, hostname_t |
| `answers[].rdata` (answer) | VALID | OK | — | dns_activity.answers (dns_answer[]) rec; dns_answer.rdata **req=required**, string_t. First-element flatten correct. |

---

## EMAIL (email_activity 4009)

email_activity.email **req=required** (object_t email).

| column | path-valid | mapping-ok | correct path if wrong | citation |
|---|---|---|---|---|
| `email.from` (sender) | VALID | OK | — | email.from rec, email_t (scalar; is_array not set) |
| `email.to[]` (recipient) | VALID | OK | — | email.to rec, email_t, **is_array=true** (CONFIRMED). First-element flatten matches scalar UDM recipient. |
| `email.subject` (subject) | VALID | OK | — | email.subject rec, string_t |
| `email.message_uid` (message_id) | VALID | OK | — | email.message_uid rec = "email header Message-ID value (RFC 5322)". Correct vs email.uid which = "unique identifier of the email **thread**" (CONFIRMED distinction). |

---

## FINDING

`vulnerabilities` is a Finding-class attribute (e.g. vulnerability_finding 2002), NOT on the 8 base classes audited. Manifest scopes it correctly to Finding classes.

| column | path-valid | mapping-ok | correct path if wrong | citation |
|---|---|---|---|---|
| `vulnerabilities[].cve.uid` (cve) | VALID (Finding classes) | OK | — | vulnerability.cve (cve obj) rec; cve.uid **req=required**, string_t = "CVE unique number". First-element flatten of vulnerabilities[] correct. |

---

## CLOUD / API (api_activity 6003)

api_activity: `api` req=required, `cloud` req=required, `resources` (resource_details[]) rec, `src_endpoint` req.

| column | path-valid | mapping-ok | correct path if wrong | citation |
|---|---|---|---|---|
| `cloud.provider` (cloud_provider) | VALID | OK | — | cloud.provider **req=required**, string_t |
| `cloud.account.uid` (cloud_account_id) | VALID | OK | — | cloud.account (account) opt; account.uid rec, string_t |
| `cloud.account.name` (cloud_account_name) | VALID | OK | — | account.name rec, string_t |
| `cloud.region` (cloud_region) | VALID | OK | — | cloud.region rec, string_t (manifest labels "recommended" — matches) |
| `api.service.name` (cloud_service) | VALID | OK | — | api.service (service obj) opt; service.name rec, string_t |
| `api.operation` (none/native) | VALID | OK | — | api.operation **req=required**, string_t = "Verb/Operation associated with the request". Correct native-only promotion. |
| `resources[].type` (resource_type) | VALID | OK | — | resource_details.type **opt**, string_t |
| `resources[].uid` (resource_id) | VALID | OK | — | resource_details.uid rec, resource_uid_t |
| `resources[].name` (resource_name) | VALID | OK | — | resource_details.name rec, string_t |
| `activity_id` (change_type) | VALID | OK (lossy, documented) | — | CRUD action via activity_id enum; UDM 'permission_change' unrepresentable. Documented reuse, fine. |

---

## ENRICHMENT — GEO / ASN (dual-mode, src_endpoint/dst_endpoint.location & .autonomous_system)

network_endpoint.location (opt, location) and network_endpoint.autonomous_system (opt, AS).

| column | path-valid | mapping-ok | correct path if wrong | citation |
|---|---|---|---|---|
| `src_endpoint.location.country` (enriched_src_country_code) | VALID | OK | — | location.country rec = **ISO 3166-1 Alpha-2 code** (CONFIRMED). Correctly maps to country_**code**, not country name. |
| `src_endpoint.location.continent` (enriched_src_continent) | VALID | OK | — | location.continent rec = "name of the continent" (name, not code — matches manifest) |
| `src_endpoint.autonomous_system.number` (enriched_src_asn) | VALID | OK | — | autonomous_system.number rec, integer_t → UInt32 |
| `src_endpoint.autonomous_system.name` (enriched_src_as_name) | VALID | OK | — | autonomous_system.name rec, string_t |
| `dst_endpoint.location.country` (enriched_dest_country_code) | VALID | OK | — | mirror |
| `dst_endpoint.location.continent` (enriched_dest_continent) | VALID | OK | — | mirror |
| `dst_endpoint.autonomous_system.number` (enriched_dest_asn) | VALID | OK | — | mirror |
| `dst_endpoint.autonomous_system.name` (enriched_dest_as_name) | VALID | OK | — | mirror |

---

## ENRICHMENT — IOC / CUSTOM (enrichments[] by name)

base_event.enrichments (opt, enrichment[]) — CONFIRMED present on all classes.

| column | path-valid | mapping-ok | correct path if wrong | citation |
|---|---|---|---|---|
| `enrichments[name=ioc_src_ip_threat_type].value` | VALID | OK | — | enrichment.name req + enrichment.value req. By-name selection valid. |
| `enrichments[name=ioc_dest_ip_threat_type].value` | VALID | OK | — | same |
| `enrichments[name=ioc_domain_threat_type].value` | VALID | OK | — | same |
| `enrichments[name=ioc_hash_threat_type].value` | VALID | OK | — | same |
| `enrichments[name=custom_src_ip_tags].value` | VALID | OK | — | same (UDM Array reconstructed at query layer; documented) |
| `enrichments[name=custom_dest_ip_tags].value` | VALID | OK | — | same |

---

## METADATA (provenance)

| column | path-valid | mapping-ok | correct path if wrong | citation |
|---|---|---|---|---|
| `metadata.product.name` (vendor_product) | VALID | OK | — | metadata.product req; product.name rec, string_t |
| `metadata.product.vendor_name` (vendor) | VALID | OK | — | product.vendor_name rec, string_t |
| `metadata.product.feature.name` (none) | VALID | OK | — | product.feature (feature) opt; feature.name rec, string_t |
| `metadata.log_name` (none) | VALID | OK | — | metadata.log_name rec, string_t |
| `metadata.log_provider` (none) | VALID | OK | — | metadata.log_provider opt, string_t |
| `metadata.uid` (id) | VALID | OK | — | metadata.uid opt (see Special #6) |
| `metadata.version` (none) | VALID | OK | — | metadata.version **req=required**, string_t |
| `metadata.correlation_uid` (none) | VALID | OK | — | metadata.correlation_uid opt, string_t |

---

## PREVALENCE (nano-computed UInt16, keyed on OCSF source paths)

These are nano internal counts; the "ocsf_path" is the **key source**, not a promoted OCSF attr.

| column | key path valid | mapping-ok | notes |
|---|---|---|---|
| `prevalence_file_hash` ← file.hashes[3].value | VALID | OK | keyed on file SHA-256 |
| `prevalence_process_hash` ← actor.process.file.hashes[3].value | VALID | OK⚠ | keyed on **actor** process hash — inherits the same actor-vs-process inversion as PROCESS section; should key on `process.file.hashes` for 1007 |
| `prevalence_dest_domain` ← dst_endpoint.hostname | VALID | OK | |
| `prevalence_dest_ip` ← dst_endpoint.ip | VALID | OK | |

---

# PRIORITIZED FIX LIST

## (a) PATH-INVALID — must change DDL (the promoted JSON path does not resolve on the target class)

1. **`url.hostname` (url_domain) and `url.url_string` (url) on HTTP Activity 4002.**
   http_activity has **NO top-level `url`** attribute (CONFIRMED on live server). These columns are
   empty for every 4002 row. **DDL fix:** add `http_request.url.hostname` and
   `http_request.url.url_string` MATERIALIZED columns (extract `event.http_request.url.{hostname,url_string}`).
   Keep the top-level `url.*` columns — they are valid and correct for **network_activity 4001**
   (which DOES have top-level `url`). Net: HTTP URL data needs the `http_request.url.*` paths;
   today only `http_request.url.path` is promoted, so url_domain and full-url are unpopulated for HTTP.

   *(No other path is outright invalid — every other dotted path resolves through real 1.8.0 attributes
   with compatible types.)*

## (b) MAPPING-WRONG — must change manifest udm_field→column (path resolves but points at the wrong OCSF home)

2. **PROCESS primary/default inverted for System classes (process_activity 1007, and file 1001 actor).**
   OCSF `process` (req=required) = the subject "launched/injected/opened/terminated"; `actor.process`
   = "the process that **initiated** the activity" = the **parent**. The manifest makes `actor.process.*`
   the **default** promotion for UDM process_name/command_line/process_id/process_guid/process_hash.
   That maps the UDM *primary* process to OCSF's *parent*. **Fix the manifest resolution** so the
   primary/default for class_uid∈{1007,1001} is the top-level `process.*`, with `actor.process.*` as the
   parent/initiator (and COALESCE for classes that only carry an actor process):
   - process_name → **process.name**
   - command_line → **process.cmd_line**
   - process_id → **process.pid**
   - process_guid → **process.uid**
   - process_hash → **process.file.hashes[algorithm_id=3].value**
   - prevalence_process_hash key → **process.file.hashes[...]**

3. **`parent_command_line` → `actor.process.parent_process.cmd_line` is the GRANDPARENT, not the parent.**
   For 1007, the parent of the subject `process` is `process.parent_process` (or equivalently the
   initiator `actor.process` itself). **Fix:** map parent_command_line →
   **`process.parent_process.cmd_line`** (parent of the subject); `actor.process.cmd_line` is an
   acceptable alternate since the initiator is the parent. `actor.process.parent_process.cmd_line`
   is one level too deep.

## (c) Correct as-is (verified PATH-VALID + MAPPING-OK)

Everything else: all TAXONOMY/CORE; all NETWORK endpoint/port/mac/hostname/`connection_info.protocol_num`/`traffic.*`
(with a flagged **direction-semantics caveat** on bytes/packets in vs out — names are exact, confirm UDM
direction convention matches OCSF "in = dest→source"); all IDENTITY (user/actor.user/domain/uid); FILE
(name/path/hashes[3]/file_action); AUTH (auth_protocol_id/auth_protocol/status_id/session.uid/is_mfa);
WEB http_method/user_agent/http_response.code and http_request.url.path; DNS query.hostname & answers[].rdata;
EMAIL from/to[]/subject/message_uid; FINDING vulnerabilities[].cve.uid; all CLOUD/API
(cloud.*/api.service.name/api.operation/resources[].*/change_type); all ENRICH GEO/ASN; all ENRICH IOC/custom
enrichments[]; all METADATA; remaining PREVALENCE.

### Specials resolved
- **#1 (process role):** CONFIRMED inverted — see fix (b)2/(b)3.
- **#2 (url on HTTP):** CONFIRMED top-level `url` invalid on 4002, valid on 4001 — see fix (a)1.
- **#3 (connection_info):** CONFIRMED attribute is `connection_info` (object_type network_connection_info); `protocol_num` is a real attr. Correct.
- **#4 (answers.rdata):** CONFIRMED `answers` (dns_answer[]) and `rdata` (req) valid. Correct.
- **#5 (auth_result→status_id, auth_type→auth_protocol_id):** CONFIRMED both valid; status_id base/auth, auth_protocol_id authentication-class. Correct.
- **#6 (metadata.uid):** CONFIRMED = producer OCSF event id (string, optional); CH row id correctly server-owned. Correct.
