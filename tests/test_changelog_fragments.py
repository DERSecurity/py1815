"""The changelog fragment rules, and that the committed fragments obey them.

The assembler is loaded by path rather than imported: `scripts/` is a directory
of scripts rather than a package, and making it one to satisfy a test would be
the test changing the shape of the repository.
"""

from __future__ import annotations

import importlib.util
import pathlib

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "build_changelog.py"


def _load():
    spec = importlib.util.spec_from_file_location("build_changelog", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


build_changelog = _load()
FragmentError = build_changelog.FragmentError

GOOD = "**A thing changed (#42).** And here is the consequence a consumer sees."


class TestTheCommittedFragments:
    """Whatever is pending right now has to be releasable."""

    def test_every_fragment_here_is_valid(self):
        """A fragment that breaks a rule should fail in CI rather than at
        release, when the person cutting it has the least context."""
        build_changelog.read_fragments()

    def test_the_directory_documents_itself(self):
        readme = _ROOT / "changelog.d" / "README.md"
        assert readme.is_file(), "changelog.d/README.md is how anyone learns the convention"


class TestTheFilename:
    @pytest.mark.parametrize("category", build_changelog.CATEGORIES)
    def test_each_keep_a_changelog_category_parses(self, category):
        reference, parsed = build_changelog.parse_fragment_name(f"42.{category}.md")
        assert (reference, parsed) == (42, category)

    @pytest.mark.parametrize(
        "name",
        [
            pytest.param("fixed.md", id="no reference"),
            pytest.param("#42.fixed.md", id="reference with a hash"),
            pytest.param("42.repaired.md", id="category nobody renders"),
            pytest.param("42.fixed.txt", id="not markdown"),
            pytest.param("42.Fixed.md", id="capitalised category"),
        ],
    )
    def test_a_name_that_would_sort_oddly_is_refused(self, name):
        """Refused rather than filed under a heading nobody reads."""
        with pytest.raises(FragmentError):
            build_changelog.parse_fragment_name(name)


class TestTheBody:
    def test_a_bolded_opener_is_accepted(self):
        build_changelog.check_style("42.fixed.md", GOOD)

    def test_an_entry_without_a_bolded_opener_is_refused(self):
        """The opener is what a reader scanning a released section takes the
        change from."""
        with pytest.raises(FragmentError):
            build_changelog.check_style("42.fixed.md", "A thing changed (#42), quietly.")

    def test_an_empty_bold_is_not_a_summary(self):
        with pytest.raises(FragmentError):
            build_changelog.check_style("42.fixed.md", "**** (#42)")

    def test_a_summary_may_wrap(self):
        """A bound tight enough to reject a long bolded run rejects these."""
        build_changelog.check_style(
            "42.fixed.md",
            "**A summary long enough that its author wrapped it across more than\n"
            "one line before closing the bold (#42).** Then the body.",
        )


class TestTheRelease:
    def test_a_release_folds_fragments_and_keeps_history(self, tmp_path):
        changelog = tmp_path / "CHANGELOG.md"
        changelog.write_text(
            "# Changelog\n\n## [Unreleased]\n\nNothing yet.\n\n"
            "## [0.1.0] - 2026-01-01\n\n- First.\n",
            encoding="utf-8",
        )
        fragments = tmp_path / "changelog.d"
        fragments.mkdir()
        (fragments / "42.added.md").write_text(GOOD, encoding="utf-8")

        consumed = build_changelog.release(
            "0.2.0", when="2026-02-02", changelog=str(changelog), fragment_dir=str(fragments)
        )

        text = changelog.read_text(encoding="utf-8")
        assert "## [0.2.0] - 2026-02-02" in text
        assert "A thing changed (#42)" in text
        # The older section survives: a tooling change must not lose history.
        assert "## [0.1.0] - 2026-01-01" in text and "- First." in text
        # And Unreleased is left in place for the next entry, carrying the
        # placeholder rather than nothing, since an empty heading reads as a
        # mistake and the placeholder is the repository's convention.
        assert text.index("## [Unreleased]") < text.index("## [0.2.0]")
        unreleased = text[text.index("## [Unreleased]") : text.index("## [0.2.0]")]
        assert "Nothing yet." in unreleased
        # The placeholder is not content, so it does not travel into the release.
        released = text[text.index("## [0.2.0]") : text.index("## [0.1.0]")]
        assert "Nothing yet." not in released
        assert [pathlib.Path(p).name for p in consumed] == ["42.added.md"]

    def test_a_release_of_real_unreleased_entries_still_restores_the_placeholder(self, tmp_path):
        """Entries written straight under Unreleased are released, and the
        heading they leave behind gets the placeholder back."""
        changelog = tmp_path / "CHANGELOG.md"
        changelog.write_text(
            "# Changelog\n\n## [Unreleased]\n\n### Fixed\n\n- A hand-written fix.\n\n"
            "## [0.1.0] - 2026-01-01\n\n- First.\n",
            encoding="utf-8",
        )
        fragments = tmp_path / "changelog.d"
        fragments.mkdir()

        build_changelog.release(
            "0.2.0", when="2026-02-02", changelog=str(changelog), fragment_dir=str(fragments)
        )

        text = changelog.read_text(encoding="utf-8")
        unreleased = text[text.index("## [Unreleased]") : text.index("## [0.2.0]")]
        released = text[text.index("## [0.2.0]") : text.index("## [0.1.0]")]
        assert "Nothing yet." in unreleased and "A hand-written fix." not in unreleased
        assert "A hand-written fix." in released and "Nothing yet." not in released

    def test_only_the_leading_placeholder_is_removed(self, tmp_path):
        """The same words deeper in a hand-written body are that body's own."""
        changelog = tmp_path / "CHANGELOG.md"
        changelog.write_text(
            "# Changelog\n\n## [Unreleased]\n\nNothing yet.\n\n### Changed\n\n"
            "- The empty state now reads:\n\n  Nothing yet.\n\n"
            "## [0.1.0] - 2026-01-01\n\n- First.\n",
            encoding="utf-8",
        )
        fragments = tmp_path / "changelog.d"
        fragments.mkdir()

        build_changelog.release(
            "0.2.0", when="2026-02-02", changelog=str(changelog), fragment_dir=str(fragments)
        )

        text = changelog.read_text(encoding="utf-8")
        released = text[text.index("## [0.2.0]") : text.index("## [0.1.0]")]
        assert released.count("Nothing yet.") == 1, "the hand-written line was folded intact"
        assert "The empty state now reads:" in released

    def test_a_release_without_an_unreleased_heading_is_refused(self, tmp_path):
        changelog = tmp_path / "CHANGELOG.md"
        changelog.write_text(
            "# Changelog\n\n## [0.1.0] - 2026-01-01\n\n- First.\n", encoding="utf-8"
        )
        fragments = tmp_path / "changelog.d"
        fragments.mkdir()

        with pytest.raises(FragmentError):
            build_changelog.release("0.2.0", changelog=str(changelog), fragment_dir=str(fragments))
