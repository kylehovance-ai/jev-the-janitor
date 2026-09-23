"""What `pip install` ships must be enough to run.

Through 0.2.1 the wheel held the `janitor` package only and DEFAULT_TAXONOMY resolved to
`<checkout>/taxonomies/vault_memory.yaml`, two levels above the package. An editable
install hid this; `pip install git+https://...` could not load the default taxonomy.
CI's `test-installed` leg is the other half of this test: a non-editable install, run
from a directory that is not the checkout.
"""

from pathlib import Path

import janitor
from janitor.schema import DEFAULT_TAXONOMY, load_taxonomy, taxonomy_fingerprint


def test_default_taxonomy_lives_inside_the_package():
    package_dir = Path(janitor.__file__).resolve().parent
    assert DEFAULT_TAXONOMY.is_relative_to(package_dir)
    assert DEFAULT_TAXONOMY.exists()
    assert load_taxonomy()["questions"]["bucket"]["options"]


def test_the_default_fingerprint_is_pinned():
    """The fingerprint is a content hash, so cache keys and stamped votes survive a move of the
    file. 65bd5bfc7207 through 0.4.2; be00a24c7a68 since 0.4.3, when the two instruction
    sentences moved into the file at identical wording (the wire was measured byte-identical).
    If this changes, the README's calibration note and illustrative output must say so."""
    assert taxonomy_fingerprint() == "be00a24c7a68"
