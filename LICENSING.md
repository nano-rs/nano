# Licensing

This repository is **dual-licensed**. The license that applies to a given
file is declared via an SPDX-License-Identifier comment at the top of that
file. Two licenses are in use:

| SPDX identifier | Applies to | License text |
|---|---|---|
| `AGPL-3.0-or-later` | The open-core engine | [`LICENSE`](./LICENSE) |
| `LicenseRef-NanoProprietary` | Proprietary enterprise paths | not redistributable |

## What's AGPL-3.0-or-later

The default for this repository. Everything under `nanosiem-core/`,
`nanosiem-search/`, `nanosiem-api/`, `nanosiem-web/src/` (except
`enterprise/`), and the open-source tools is licensed under the GNU Affero
General Public License v3.0 or later. The full text is in
[`LICENSE`](./LICENSE).

If you contribute to AGPL portions, your contribution is accepted under
AGPL-3.0-or-later via the [contributor license agreement](./.github/ICLA.md).

## What's proprietary

The enterprise edition adds proprietary code owned by Nano LLC. That code is
not part of this repository and is not licensed under AGPL-3.0; it is compiled
in only by the enterprise build (`cargo build --features enterprise`,
`VITE_EDITION=enterprise`), which this repository cannot produce on its own.
The AGPL portions are published here by the sync-mirror workflow.

## Commercial licensing

If AGPL doesn't fit your deployment (for example, you ship the engine as
part of a closed-source product without distributing source), a commercial
license is available. Contact <hello@nano.rs>.

## Contributions

Community contributions are accepted under the AGPL portions only. The CLA
([`.github/ICLA.md`](./.github/ICLA.md)) grants Nano LLC the right to
sublicense your contribution under the proprietary terms used by the
enterprise build. We commit not to relicense the AGPL portions away from
AGPL-3.0-or-later (or successor at least as permissive). See the CLA for
the full terms.

## Questions

<legal@nano.rs>.
