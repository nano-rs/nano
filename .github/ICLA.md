<!-- Adapted from Apache ICLA V2.2 (https://www.apache.org/licenses/icla.pdf). -->

# Individual Contributor License Agreement ("Agreement") V1.0

Thank you for your interest in nano (the "Project"), maintained by Nano LLC
(the "Company"). To clarify the intellectual property license granted with
Contributions from any person or entity, the Company must have on file a
signed Contributor License Agreement ("CLA") from each Contributor,
indicating agreement with the license terms below. This agreement is for
your protection as a Contributor as well as the protection of the Company
and its users. It does not change your rights to use your own Contributions
for any other purpose.

In practice, you sign this Agreement once via the
[cla-assistant.io](https://cla-assistant.io) web flow on your first pull
request to the public nano repository. cla-assistant collects your name,
email, and GitHub identity, records your acceptance of the terms below, and
gates merge of your PR until acceptance is recorded. Subsequent PRs from
the same GitHub account are auto-recognised.

Read this document carefully before signing.

## Required information (collected via cla-assistant)

The cla-assistant flow will record:

- Your **full name** (legal name; will be public unless you provide a public alias)
- Your **public name** (optional — defaults to your full name)
- Your **email address** (public)
- Your **GitHub username** (public)
- Your **country of residence**

You retain the right to amend or withdraw your CLA acceptance by emailing
<legal@nano.rs>; withdrawal does not affect Contributions already accepted
and merged.

## Terms and conditions

You accept and agree to the following terms and conditions for Your
Contributions (present and future) that you submit to the Project. In
return, the Company commits that Your Contributions accepted into the
AGPL-3.0-licensed engine portions of the Project shall continue to be
available to the public under the GNU Affero General Public License version
3.0 (or a successor license at least as permissive in the same family),
even if the Company changes the license of new versions of the engine. The
Company further commits that the public engine repository
(`nanos-sh/nano` or any successor) shall remain publicly available
under such a license. Except for the licenses granted herein to the Company
and recipients of software distributed by the Company, You reserve all
right, title, and interest in and to Your Contributions.

### 1. Definitions

"You" (or "Your") shall mean the copyright owner or legal entity authorized
by the copyright owner that is making this Agreement with the Company. For
legal entities, the entity making a Contribution and all other entities
that control, are controlled by, or are under common control with that
entity are considered to be a single Contributor. For the purposes of this
definition, "control" means (i) the power, direct or indirect, to cause the
direction or management of such entity, whether by contract or otherwise,
or (ii) ownership of fifty percent (50%) or more of the outstanding shares,
or (iii) beneficial ownership of such entity.

"Contribution" shall mean any original work of authorship, including any
modifications or additions to an existing work, that is intentionally
submitted by You to the Company for inclusion in, or documentation of, any
of the products owned or managed by the Company (the "Work"). For the
purposes of this definition, "submitted" means any form of electronic,
verbal, or written communication sent to the Company or its
representatives, including but not limited to communication on electronic
mailing lists, source code control systems, and issue tracking systems that
are managed by, or on behalf of, the Company for the purpose of discussing
and improving the Work, but excluding communication that is conspicuously
marked or otherwise designated in writing by You as "Not a Contribution."

### 2. Grant of Copyright License

Subject to the terms and conditions of this Agreement, You hereby grant to
the Company and to recipients of software distributed by the Company a
perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable
copyright license to reproduce, prepare derivative works of, publicly
display, publicly perform, sublicense, and distribute Your Contributions
and such derivative works.

### 3. Grant of Patent License

Subject to the terms and conditions of this Agreement, You hereby grant to
the Company and to recipients of software distributed by the Company a
perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable
(except as stated in this section) patent license to make, have made, use,
offer to sell, sell, import, and otherwise transfer the Work, where such
license applies only to those patent claims licensable by You that are
necessarily infringed by Your Contribution(s) alone or by combination of
Your Contribution(s) with the Work to which such Contribution(s) was
submitted. If any entity institutes patent litigation against You or any
other entity (including a cross-claim or counterclaim in a lawsuit)
alleging that your Contribution, or the Work to which you have contributed,
constitutes direct or contributory patent infringement, then any patent
licenses granted to that entity under this Agreement for that Contribution
or Work shall terminate as of the date such litigation is filed.

### 4. Authority

You represent that you are legally entitled to grant the above license. If
your employer(s) has rights to intellectual property that you create that
includes your Contributions, you represent that you have received
permission to make Contributions on behalf of that employer, that your
employer has waived such rights for your Contributions to the Company, or
that your employer has executed a separate Corporate CLA with the Company.

### 5. Originality

You represent that each of Your Contributions is Your original creation
(see section 7 for submissions on behalf of others). You represent that
Your Contribution submissions include complete details of any third-party
license or other restriction (including, but not limited to, related
patents and trademarks) of which you are personally aware and which are
associated with any part of Your Contributions.

### 6. No Support / No Warranty

You are not expected to provide support for Your Contributions, except to
the extent You desire to provide support. You may provide support for
free, for a fee, or not at all. Unless required by applicable law or agreed
to in writing, You provide Your Contributions on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied, including,
without limitation, any warranties or conditions of TITLE, NON-INFRINGEMENT,
MERCHANTABILITY, or FITNESS FOR A PARTICULAR PURPOSE.

### 7. Third-party works

Should You wish to submit work that is not Your original creation, You may
submit it to the Company separately from any Contribution, identifying the
complete details of its source and of any license or other restriction
(including, but not limited to, related patents, trademarks, and license
agreements) of which you are personally aware, and conspicuously marking
the work as "Submitted on behalf of a third-party: [named here]".

### 8. Notification of changes

You agree to notify the Company of any facts or circumstances of which you
become aware that would make these representations inaccurate in any
respect.

---

## Why open-core needs a CLA, not just a DCO

nano follows the open-core model:

- The engine in this repository is licensed under AGPL-3.0.
- The enterprise add-ons (Cases, the pivt assistant, meloD AI wizards, risk
  scoring, incident management) live in a separate proprietary repository.

To accept Contributions into the engine **and** continue shipping the
proprietary enterprise build that incorporates engine code, the Company
needs the right to **sublicense** Your Contribution under the proprietary
terms. A Developer Certificate of Origin (DCO) does not grant that right;
this CLA does (Section 2).

This CLA does **not** transfer copyright to the Company. You retain
ownership. You grant a perpetual, worldwide, royalty-free licence —
including the right to relicense — and the Company grants you the
reciprocal commitment that Contributions to the engine will continue to be
available under AGPL-3.0 (the preamble above this section).

## Privacy

Information collected via cla-assistant is used solely to record your
acceptance of this Agreement and to verify that subsequent Contributions
are covered by it. The information becomes part of the public record of
the Project (visible on cla-assistant and on the public nano repository's
PR comments).

Inquiries about the data collected: <legal@nano.rs>.

## Corporate contributors

If you contribute on behalf of a company that holds rights to your
Contributions, you may also need a Corporate Contributor License Agreement
(CCLA) signed by an authorised representative of your employer. The CCLA
template will be added at `.github/CCLA.md` once drafted; in the interim,
contact <legal@nano.rs>.

## Questions

Open a discussion in the repository, or email <legal@nano.rs>. We'd rather
answer a question up front than have a Contribution stuck waiting on
sign-off.

---

*Adapted from the Apache Software Foundation Individual Contributor License
Agreement V2.2. Copyright (c) The Apache Software Foundation. The original
text is licensed under terms that permit derivative works for use as a CLA;
this adaptation substitutes "Nano LLC" for "Apache Software Foundation",
"the Company" for "the Foundation", reframes the reciprocal commitment to
match the open-core model, and updates the signing flow to reference
[cla-assistant.io](https://cla-assistant.io). Material changes are
documented in the file's git history.*
