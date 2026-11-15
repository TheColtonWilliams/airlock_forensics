#!/usr/bin/env python3
"""Build a tiny stand-in for the SigLIP ONNX export, for plumbing tests only.

The real SigLIP export comes from HuggingFace (pins.yml ``siglip_base_onnx``), which the
authoring environment cannot reach. This writes a model with the same interface
(``input_ids``, ``pixel_values``, optional ``attention_mask`` in; ``logits_per_image`` out) whose
logits are fixed: "neutral" always wins. It proves that ``triage_runner.py`` loads a model,
tokenises the label prompts, preprocesses images, and reports scores. It says nothing about
detection quality (task 4B.16 measures that).

Needs a Python with ``onnx`` and ``tokenizers`` (a scratch venv; never the image):

    python make-fake-siglip.py OUT_DIR NUM_LABELS
"""

from __future__ import annotations

import sys
from pathlib import Path

import onnx
from onnx import TensorProto, helper
from tokenizers import Tokenizer, models, pre_tokenizers


def build(out_dir: Path, n_labels: int) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    bias = [0.0] * n_labels
    bias[-1] = 6.0  # the last label is "neutral"
    nodes = [
        helper.make_node("ReduceMean", ["pixel_values"], ["pm"], keepdims=0),
        helper.make_node("Cast", ["input_ids"], ["idf"], to=TensorProto.FLOAT),
        helper.make_node("ReduceSum", ["idf", "axes1"], ["ids_sum"], keepdims=0),
        helper.make_node("Mul", ["ids_sum", "zero"], ["ids_zero"]),
        helper.make_node("Mul", ["pm", "zero"], ["pm_zero"]),
        helper.make_node("Add", ["ids_zero", "pm_zero"], ["z"]),
        helper.make_node("Add", ["z", "bias"], ["row"]),
        helper.make_node("Unsqueeze", ["row", "axes0"], ["logits_per_image"]),
    ]
    inits = [
        helper.make_tensor("axes1", TensorProto.INT64, [1], [1]),
        helper.make_tensor("axes0", TensorProto.INT64, [1], [0]),
        helper.make_tensor("zero", TensorProto.FLOAT, [], [0.0]),
        helper.make_tensor("bias", TensorProto.FLOAT, [n_labels], bias),
    ]
    graph = helper.make_graph(
        nodes,
        "fake_siglip",
        [
            helper.make_tensor_value_info("input_ids", TensorProto.INT64, ["n", "t"]),
            helper.make_tensor_value_info("pixel_values", TensorProto.FLOAT, [1, 3, 224, 224]),
        ],
        [helper.make_tensor_value_info("logits_per_image", TensorProto.FLOAT, [1, "n"])],
        inits,
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    onnx.save(model, str(out_dir / "model.onnx"))

    words = [
        "a",
        "photo",
        "of",
        "nudity",
        "sexual",
        "activity",
        "violence",
        "weapon",
        "gore",
        "blood",
        "injury",
        "neutral",
    ]
    vocab = {"<pad>": 0, "</s>": 1, "<unk>": 2, **{w: i + 3 for i, w in enumerate(words)}}
    tok = Tokenizer(models.WordLevel(vocab=vocab, unk_token="<unk>"))  # noqa: S106 - not a secret
    tok.pre_tokenizer = pre_tokenizers.Whitespace()
    tok.save(str(out_dir / "tokenizer.json"))


if __name__ == "__main__":
    build(Path(sys.argv[1]), int(sys.argv[2]))
