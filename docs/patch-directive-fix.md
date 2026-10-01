# Patch directive classification correction

The 3.0.0-beta.3 candidate fixes a false positive when an add/update patch
contains deletion-marker text in its file contents. Body lines begin with an
addition, removal or context prefix; only unprefixed patch headers describe
file operations. The deletion recognizer now receives those headers only.

Actual file deletion and mixed add/delete patches retain the existing denial.
Shell deletion, scratch exceptions, credential and enforcement boundaries are
unchanged. This fix does not authorize logger installation or add any deletion
exception.

Validation on the source candidate:

- Two directive extraction regression tests and the complete unit suite.
- Five classifier-only journeys: added, removed and context examples allow;
  real deletion and mixed add/delete patches deny. No deletion is executed.
- Independent review before immutable release activation.

The active hook currently prevents checking in a literal deletion-marker test
fixture. Do not evade it by encoding the marker or changing writers. The
classifier-only cases can be persisted through the normal patch tool once the
reviewed correction is active.
