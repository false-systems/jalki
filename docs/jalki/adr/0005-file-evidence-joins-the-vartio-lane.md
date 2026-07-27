# ADR-0005 — the file evidence family joins the Vartio lane

- **Status:** Proposed (2026-07-20)
- **Follows:** ADR-0003 (native `VartioSink`), ADR-0004 (D1-a bearer token, D2-a native
  runtime-map wire shape). This ADR extends the accepted ADR-0004 contract to a new
  occurrence family; it changes no decision already taken.
- **Still binding:** ADR-0002 §D4 as narrowed by ADR-0004 (neutral *content*, native
  *shape*), §D5 (strong binding mandatory), §D6 (the Vartio importer is the cross-repo
  contract), §D7 (no silent loss).
- **Driver:** `kernel.file.open` (PR #16) and `kernel.file.open_attempt` (PR #20) are
  captured, normalized, and bound — and then **dropped at the sink**. PR #27 added
  `VARTIO_SUPPORTED_TYPES` because `Importer.Jalki` refuses the file family as
  `UNSUPPORTED_EVENT`; ADR-0004 explicitly deferred widening as "a Vartio-side decision
  (add the type to the importer first)". This ADR is that decision, plus the jälki half.

## 1. Context

The file family is the only Plane-B evidence jälki produces that never reaches Vartio.
Three things are missing, in dependency order:

1. Vartio's `Importer.Jalki` has no file clauses (`@occurrence_types`, `resource/1`,
   `require_type_fields!/1`) and `RuntimeEvent` has no file fields.
2. jälki's `native_runtime_item` projects no file labels — even if the importer
   accepted the types, the wire map would carry no path.
3. jälki's `VARTIO_SUPPORTED_TYPES` excludes both types.

Two decisions gate the mechanical work: what evidence class the family carries, and
what field names ride the native map.

## 2. Decision 1 — evidence class and resource semantics

`Importer.Jalki` splits evidence into **attribution** (a bound actor did something to
a concrete resource) and **reliability** (state/failure evidence, Lähde's axis).

**Decision:** both file types are **attribution**-class, with asymmetric resource refs:

- **`kernel.file.open`** → resource `%{kind: :file, id: <path>}`. The path is
  `bpf_d_path`-resolved at the LSM gate — a real file identity, same standing as
  `:executable` on exec.
- **`kernel.file.open_attempt`** → **no resource ref**. The event carries only the
  user-requested, unresolved string (`path_resolution=unresolved` since PR #20). A
  resource ref would assert an identity the kernel never resolved. The requested path
  rides the payload's `file_context`, never `resource`.

Rejected alternative: classifying `open_attempt` as reliability. The precedent is
`kernel.tcp.connect`, which stays attribution even on `ECONNREFUSED` — *attempted*
actor→target action is attribution; the family describes actor behavior, not
infrastructure state.

## 3. Decision 2 — native map fields (the wire contract)

Per ADR-0004 D2-a the authoritative shape is Vartio's `fixtures/jalki/*.json`. The file
family adds these keys, sourced from jälki's occurrence labels:

| native key | type | present on | source label |
|---|---|---|---|
| `path` | string | `file.open` only | `resource_ref_id` (when `resource_ref_kind=file`) |
| `requested_path` | string | `open_attempt` only | `requested_path` |
| `path_resolution` | string | `open_attempt` | `path_resolution` (`unresolved`) |
| `path_truncated` | bool | both, when true | `path_truncated` |
| `coverage` | string | `file.open` | `coverage` (`lsm_gated`) |
| `errno` | number, **positive** | failures | `errno_num` **negated** (label is raw negative ret; the wire convention set by `tcp_close_errno.json` is positive, e.g. `104`) |
| `flags` | string | `file.open` | `flags` |

`coverage=lsm_gated` crosses the wire deliberately: it is data honesty ("absence of a
denial is not an allow"), not interpretation. `errno` projection is generic over the
`errno_num` label — which requires the normalize layer to actually emit it: denied
`kernel.file.open` and failed `kernel.tcp.connect` now do (closing a latent gap where
connect failures carried errno only in the Plane-A error block, which never reaches
this wire). `kernel.tcp.close` cannot carry errno yet — `TcpCloseEvent` has no ret
field; `tcp_close_errno.json` pins the *shape* for when it does (needs an eBPF
struct change, out of scope here).

Required fields (importer `require_type_fields!`): `file.open` → `pid`, `comm`,
`path`; `open_attempt` → `pid`, `comm`, `requested_path`, `errno`.

## 4. Consequence — deploy order (decoupled by a runtime gate)

The receiving importer must accept the types before jälki sends them. Rather than
enforcing that as release ordering (a human-memory invariant), the file family is
**gated at runtime**: the sink sends `kernel.file.*` only when `send_file_types` is
enabled (daemon env `JALKI_VARTIO_FILE_TYPES=1`), default **off**. Gated-off drops
surface as a distinct warning naming the flag, so operators see *config*, not
*contract* (§D7 — no silent loss).

Rollout therefore has no ordering hazard:

1. Vartio: `RuntimeEvent` file fields + importer clauses + fixtures (inert until
   jälki sends the types).
2. jälki: projection + widened `VARTIO_SUPPORTED_TYPES` + the gate — deployable any
   time; flipping the env flag on before Vartio ships costs permanent per-item
   rejects (`PartialFailure` noise), never corruption.
3. Once both are live: set `JALKI_VARTIO_FILE_TYPES=1` on the DaemonSet. A later
   ADR may retire the flag in favor of receiver-advertised capabilities (see §6).

## 5. Evidence

New Vartio fixtures `file_open_denied.json` / `file_open_attempt_enoent.json` +
importer tests; jälki-side projection tests mirror them key-for-key so the two repos
pin the same wire shape from both ends. Sink tests cover both gate positions.

## 6. Follow-ups deliberately out of scope

- **Capability negotiation.** Static type lists mirrored in two repos (plus the §4
  flag) is the weakest part of the ingress contract. The receiver knows what it
  supports; it should advertise it (or treat unsupported as an explicit *skip*, not
  an error), eliminating send-side lists for every future type. ADR-scale change to
  the source-ingress protocol — needs its own proposal. **Deferred by the rule of
  three** (the pattern vartio#65 applies to receiver extraction): jälki is today the
  *only* source-ingress producer, so a negotiated contract would be abstracted from
  one instance. **Revisit when** a second producer speaks source-ingress or a third
  type family needs a §4-style gate.
- **Attribution-without-resource.** `kernel.file.open_attempt` is the first
  attribution-class event with no resource ref. If a future corroboration lane
  assumes attribution ⇒ resource, either that assumption or this classification
  must give; a third evidence class (`:probe`) is the alternative. **Revisit when**
  the corroboration lane lands — its first test run should include the
  `file_open_attempt_enoent` fixture to surface the assumption. Flagged for the
  Vartio owner.
