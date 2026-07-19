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
denial is not an allow"), not interpretation. `errno` projection is generic — it also
closes a latent gap where tcp.connect/close failures lost their errno at the sink.

Required fields (importer `require_type_fields!`): `file.open` → `pid`, `comm`,
`path`; `open_attempt` → `pid`, `comm`, `requested_path`, `errno`.

## 4. Consequence — deploy order (hard requirement)

The two halves must land **importer first**:

1. Vartio: `RuntimeEvent` file fields + importer clauses + fixtures (deployable alone —
   inert until jälki sends the types).
2. jälki: `native_runtime_item` file projection + widen `VARTIO_SUPPORTED_TYPES`
   (must not deploy before 1 — every file item would return a permanent per-item
   reject → `PartialFailure` noise on every batch containing file evidence).

## 5. Evidence

New Vartio fixtures `file_open_denied.json` / `file_open_attempt_enoent.json` +
importer tests; jälki-side projection tests mirror them key-for-key so the two repos
pin the same wire shape from both ends.
