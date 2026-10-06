"""The pluggable L2 model (#350): which outputs are malicious, at what cut.

No model is needed. Each test writes the two files the loader reads, a
``config.json`` and optionally a ``trentina-model.json``, into a temporary
directory. Polarity is the property that matters most: a model read
backwards reports every attack clean, so an ambiguous one must not load.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from trentina.config import (
    CLASSIFIER_MODELS_DIR,
    DEFAULT_CLASSIFIER_MODEL,
    DEFAULT_CLASSIFIER_THRESHOLD,
    classifier_settings,
)
from trentina.errors import ConfigError
from trentina.quarantine import classifier

# Through the module at call time, never imported names: another test
# reloads the classifier module, and a class imported before that is no
# longer the one the reloaded functions raise.


def _model_dir(
    tmp_path: Path, id2label: dict[str, str] | None, manifest: dict[str, Any] | None = None
) -> str:
    config: dict[str, Any] = {"architectures": ["SequenceClassification"]}
    if id2label is not None:
        config["id2label"] = id2label
    (tmp_path / "config.json").write_text(json.dumps(config))
    if manifest is not None:
        (tmp_path / classifier.MANIFEST_FILE).write_text(json.dumps(manifest))
    return str(tmp_path)


class TestPolarity:
    def test_horizon_labels_resolve_without_a_manifest(self, tmp_path: Path) -> None:
        model = classifier.resolve_model(_model_dir(tmp_path, {"0": "SAFE", "1": "INJECTION"}))
        assert model.malicious == (1,)
        assert model.threshold == DEFAULT_CLASSIFIER_THRESHOLD

    def test_benign_at_index_one_is_read_the_right_way_round(self, tmp_path: Path) -> None:
        model = classifier.resolve_model(_model_dir(tmp_path, {"0": "MALICIOUS", "1": "BENIGN"}))
        assert model.malicious == (0,)

    def test_every_non_benign_label_counts(self, tmp_path: Path) -> None:
        labels = {"0": "BENIGN", "1": "INJECTION", "2": "JAILBREAK"}
        assert classifier.resolve_model(_model_dir(tmp_path, labels)).malicious == (1, 2)

    def test_unnamed_labels_without_a_manifest_refuse(self, tmp_path: Path) -> None:
        with pytest.raises(classifier.ModelManifestError, match="polarity"):
            classifier.resolve_model(_model_dir(tmp_path, {"0": "LABEL_0", "1": "LABEL_1"}))

    def test_labels_that_say_nothing_about_attacks_refuse(self, tmp_path: Path) -> None:
        """A sentiment head would load with POSITIVE read as an attack."""
        with pytest.raises(classifier.ModelManifestError, match="polarity"):
            classifier.resolve_model(_model_dir(tmp_path, {"0": "NEGATIVE", "1": "POSITIVE"}))

    def test_one_unknown_label_beside_known_ones_refuses(self, tmp_path: Path) -> None:
        labels = {"0": "SAFE", "1": "INJECTION", "2": "OFFTOPIC"}
        with pytest.raises(classifier.ModelManifestError, match="polarity"):
            classifier.resolve_model(_model_dir(tmp_path, labels))

    def test_no_labels_at_all_refuses(self, tmp_path: Path) -> None:
        """Prompt Guard 2's config.json carries none; its manifest must say."""
        with pytest.raises(classifier.ModelManifestError, match="polarity"):
            classifier.resolve_model(_model_dir(tmp_path, None))

    def test_all_benign_or_all_malicious_refuses(self, tmp_path: Path) -> None:
        with pytest.raises(classifier.ModelManifestError):
            classifier.resolve_model(_model_dir(tmp_path, {"0": "INJECTION", "1": "JAILBREAK"}))


class TestManifest:
    def test_indices_name_an_unlabelled_model(self, tmp_path: Path) -> None:
        manifest = {"id": "prompt-guard-2-86m", "revision": "abc", "malicious_indices": [1]}
        model = classifier.resolve_model(_model_dir(tmp_path, None, manifest))
        assert (model.id, model.revision, model.malicious) == ("prompt-guard-2-86m", "abc", (1,))

    def test_labels_in_the_manifest_must_exist(self, tmp_path: Path) -> None:
        manifest = {"malicious_labels": ["INJECTION", "JAILBREAK"]}
        with pytest.raises(classifier.ModelManifestError, match="lacks"):
            classifier.resolve_model(
                _model_dir(tmp_path, {"0": "SAFE", "1": "INJECTION"}, manifest)
            )

    def test_negative_index_refuses(self, tmp_path: Path) -> None:
        with pytest.raises(classifier.ModelManifestError):
            classifier.resolve_model(_model_dir(tmp_path, None, {"malicious_indices": [-1]}))

    def test_the_manifest_sets_the_threshold(self, tmp_path: Path) -> None:
        manifest = {"malicious_labels": ["INJECTION"], "threshold": 0.7}
        model = classifier.resolve_model(
            _model_dir(tmp_path, {"0": "SAFE", "1": "INJECTION"}, manifest)
        )
        assert model.threshold == 0.7

    def test_an_override_beats_the_manifest(self, tmp_path: Path) -> None:
        manifest = {"malicious_labels": ["INJECTION"], "threshold": 0.7}
        path = _model_dir(tmp_path, {"0": "SAFE", "1": "INJECTION"}, manifest)
        assert classifier.resolve_model(path, threshold_override=0.4).threshold == 0.4

    @pytest.mark.parametrize("threshold", [0.0, -0.1, 1.5])
    def test_a_threshold_outside_the_unit_interval_refuses(
        self, tmp_path: Path, threshold: float
    ) -> None:
        path = _model_dir(tmp_path, {"0": "SAFE", "1": "INJECTION"}, {"threshold": threshold})
        with pytest.raises(classifier.ModelManifestError, match="threshold"):
            classifier.resolve_model(path)

    def test_id_defaults_to_the_directory_name(self, tmp_path: Path) -> None:
        sub = tmp_path / "my-model"
        sub.mkdir()
        model = classifier.resolve_model(_model_dir(sub, {"0": "SAFE", "1": "INJECTION"}))
        assert model.id == "my-model"
        assert model.revision == "unpinned"

    def test_two_unpinned_exports_do_not_share_a_revision(self, tmp_path: Path) -> None:
        """The revision is in the verdict stamp: a swapped graph must re-judge."""
        a, b = tmp_path / "a", tmp_path / "b"
        for d, graph in ((a, b"one"), (b, b"other graph")):
            d.mkdir()
            (d / "model.onnx").write_bytes(graph)
            _model_dir(d, {"0": "SAFE", "1": "INJECTION"})
        rev_a = classifier.resolve_model(str(a)).revision
        assert rev_a.startswith("unpinned-")
        assert rev_a != classifier.resolve_model(str(b)).revision


class TestOutputWidth:
    def _session(self, shape: list[Any]) -> MagicMock:
        session = MagicMock()
        session.get_outputs.return_value = [MagicMock(shape=shape)]
        return session

    def test_fits(self) -> None:
        classifier._check_output_width(
            self._session(["batch", 2]), classifier.ModelInfo("m", "", 0.5, malicious=(1,))
        )

    def test_an_index_past_the_outputs_refuses(self) -> None:
        with pytest.raises(classifier.ModelManifestError):
            classifier._check_output_width(
                self._session(["batch", 2]), classifier.ModelInfo("m", "", 0.5, malicious=(2,))
            )

    def test_covering_every_output_refuses(self) -> None:
        with pytest.raises(classifier.ModelManifestError):
            classifier._check_output_width(
                self._session(["batch", 2]), classifier.ModelInfo("m", "", 0.5, malicious=(0, 1))
            )

    def test_a_dynamic_width_refuses(self) -> None:
        with pytest.raises(classifier.ModelManifestError):
            classifier._check_output_width(
                self._session(["batch", "labels"]),
                classifier.ModelInfo("m", "", 0.5, malicious=(1,)),
            )


class TestSelection:
    def _settings(self, **env: str) -> tuple[float | None, str, str]:
        base = {"CLASSIFIER_THRESHOLD": "", "CLASSIFIER_MODEL": "", "CLASSIFIER_MODEL_PATH": ""}
        with patch.dict("os.environ", {**base, **env}):
            return classifier_settings()

    def test_defaults_to_the_shipped_model(self) -> None:
        assert self._settings() == (
            None,
            DEFAULT_CLASSIFIER_MODEL,
            f"{CLASSIFIER_MODELS_DIR}/{DEFAULT_CLASSIFIER_MODEL}",
        )

    def test_a_name_selects_a_shipped_model(self) -> None:
        _, name, path = self._settings(CLASSIFIER_MODEL="prompt-guard-2-86m")
        assert (name, path) == ("prompt-guard-2-86m", "/models/prompt-guard-2-86m")

    def test_a_path_wins_over_a_name(self) -> None:
        _, _, path = self._settings(
            CLASSIFIER_MODEL="prompt-guard-2-86m", CLASSIFIER_MODEL_PATH="/mnt/candidate"
        )
        assert path == "/mnt/candidate"

    @pytest.mark.parametrize("name", ["../etc", "a/b", "..", "."])
    def test_a_name_cannot_walk_out_of_the_models_dir(self, name: str) -> None:
        with pytest.raises(ConfigError, match="CLASSIFIER_MODEL_PATH"):
            self._settings(CLASSIFIER_MODEL=name)

    def test_a_threshold_override_is_read(self) -> None:
        assert self._settings(CLASSIFIER_THRESHOLD="0.65")[0] == 0.65
