# Control catalog layout

The catalog separates control *definitions* from the per-spec-version
*catalogs* that reference them, so a new SLSA spec release never
duplicates control definitions:

- `controls/<track>/*.yaml` — control definitions: id, title,
  description, track and CEL checks. Definitions carry **no**
  `slsaLevel`; levels are a property of a spec version, not of the
  control. IDs must be unique within a track.
- `specs/<track>/<version>/core.yaml` — the verification catalog for
  one SLSA spec version: the list of control IDs the spec requires and
  the level each one holds in that release. Adding support for a new
  spec version means adding one manifest here (referencing new or
  existing definitions), nothing else.
- `specs/<track>/buildType.yaml` — custom builder-specific controls;
  not spec criteria, therefore unversioned and unleveled.

Spec resolution: criteria carry forward across releases, so a request
for spec version S uses the newest manifest at or below S (`--spec 1.2`
on the build track resolves to `build/1.0/core`, whose criteria are
unchanged since v1.0). Requesting a version older than a track's first
manifest is an error — the track did not exist in that spec.
