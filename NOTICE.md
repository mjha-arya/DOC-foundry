# NOTICE — third-party content redistributed in this repository

The original code in this repository is MIT-licensed (see `LICENSE`).

The **knowledge base under `rule_corpus/`** is not original work. It is derived
from open-source detection and threat-intelligence projects and is redistributed
here under their respective licences, with attribution as required. If you fork,
vendor, or redistribute this repository, these obligations travel with it.

`rule_corpus/` is used only to **ground the proposing agents** (Blue retrieves
detection prior art; Red retrieves catalogued adversary techniques). It is never
consulted by the deterministic proof core and never enters the reproducibility
hash — see `src/knowledge_base.py`.

---

## SigmaHQ — `rule_corpus/blue.jsonl`, `rule_corpus/blue/`

**3,769 documents** derived from the SigmaHQ rule set. Each Sigma rule is
converted into a retrieval document (title, ATT&CK techniques, rule text).

- Project: https://github.com/SigmaHQ/sigma
- Licence: **Detection Rule License (DRL) 1.1** — https://github.com/SigmaHQ/sigma/blob/master/LICENSE.Detection.Rules.md
- The DRL permits use and redistribution with attribution to the original rule
  authors. Individual rules retain their own `author` field, which is preserved
  in the derived documents.

Copyright and credit remain with the respective SigmaHQ rule authors and
contributors.

## MITRE ATT&CK® — `rule_corpus/red.jsonl`, `rule_corpus/red/`

**697 documents** derived from the MITRE ATT&CK Enterprise STIX bundle
(`attack-pattern` objects: techniques and sub-techniques).

- Project: https://attack.mitre.org/
- Terms of use: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/

> © 2026 The MITRE Corporation. This work is reproduced and distributed with the
> permission of The MITRE Corporation.

MITRE ATT&CK® is a registered trademark of The MITRE Corporation. This project
is not affiliated with, endorsed by, or sponsored by MITRE.

## LOLBAS — `rule_corpus/red/`

Seed documents describing living-off-the-land binary abuse.

- Project: https://github.com/LOLBAS-Project/LOLBAS
- Licence: **MIT**

## Atomic Red Team — `fixtures/atomic/`

Atomic test definitions used as real attacker-command telemetry for the
positive test corpus (`--corpus atomic`).

- Project: https://github.com/redcanaryco/atomic-red-team
- Licence: **MIT** (with the Atomic Red Team usage terms)

---

## Rebuilding the corpus

`rule_corpus/` is generated, not hand-written. To rebuild it from current
upstream sources:

```bash
python tools/build_rag_corpus.py
```

If you would rather not redistribute third-party detection content at all,
delete `rule_corpus/` and rebuild locally — the tool degrades to ungrounded
proposals rather than failing.
