#!/usr/bin/env python3
"""Export an L2 classifier for Trentina: pinned download, ONNX, manifest (#350).

Runs in the Containerfile's model-builder stage, which has torch and optimum;
the runtime image has neither. Also the way to try a candidate model: run it
in that same builder image, mount the output directory into the gateway and
point ``CLASSIFIER_MODEL_PATH`` at it.

    python scripts/export_l2_model.py --repo ORG/NAME --revision SHA \\
        --out /models/NAME --id NAME --threshold 0.5 --malicious-labels INJECTION

The manifest (``trentina-model.json``) is what ``quarantine/classifier.py``
reads to know which outputs are malicious and at what threshold; see
``resolve_model`` there. Name the malicious outputs by label when the model's
``config.json`` labels them, by index when it does not.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

FILES = [
    "config.json",
    "model.safetensors",
    "tokenizer.json",
    "tokenizer_config.json",
    "special_tokens_map.json",
]
"""What a sequence-classification export needs. Named rather than globbed, so
a repo's training code, eval data and pickles are never downloaded."""

COMMIT_SHA_LENGTH = 40
"""A pin is a full commit SHA: a branch or tag can move under the image."""


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--repo", required=True)
    p.add_argument("--revision", required=True, help="A commit SHA, never a branch.")
    p.add_argument("--out", required=True)
    p.add_argument("--id", required=True)
    p.add_argument("--license", default="")
    p.add_argument("--threshold", type=float, required=True)
    polarity = p.add_mutually_exclusive_group(required=True)
    polarity.add_argument("--malicious-labels", nargs="+")
    polarity.add_argument("--malicious-indices", nargs="+", type=int)
    args = p.parse_args()

    if len(args.revision) != COMMIT_SHA_LENGTH or any(
        c not in "0123456789abcdef" for c in args.revision
    ):
        p.error("--revision must be a full 40-character commit SHA")

    from huggingface_hub import snapshot_download  # builder-stage dependency

    with tempfile.TemporaryDirectory() as src:
        snapshot_download(args.repo, revision=args.revision, local_dir=src, allow_patterns=FILES)
        if not (Path(src) / "model.safetensors").is_file():
            print(f"{args.repo}@{args.revision} has no model.safetensors", file=sys.stderr)
            return 1
        from optimum.exporters.onnx import main_export

        main_export(src, output=args.out, task="text-classification")

    manifest = {
        "id": args.id,
        "source": args.repo,
        "revision": args.revision,
        "license": args.license,
        "threshold": args.threshold,
    }
    if args.malicious_labels:
        manifest["malicious_labels"] = args.malicious_labels
    else:
        manifest["malicious_indices"] = args.malicious_indices
    (Path(args.out) / "trentina-model.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"exported {args.repo}@{args.revision} to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
