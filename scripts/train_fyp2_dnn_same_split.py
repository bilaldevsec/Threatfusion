#!/usr/bin/env python3
"""Train the same-split PyTorch DNN on the canonical 14 UNSW-NB15 features.

The four official raw captures are read in file order. ``rate`` is
``(spkts + dpkts) / dur`` when duration is positive. Standardization mean and
standard deviation are fit on the train stratum only. The frozen Random Forest
artifact is scored read-only for the binary comparison and is not rewritten.
"""

from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from torch import nn

SEED = 42
FEATURE_NAMES: tuple[str, ...] = (
    "dur",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "rate",
    "sttl",
    "dttl",
    "sload",
    "dload",
    "sinpkt",
    "dinpkt",
    "sjit",
    "djit",
)
CATEGORIES: tuple[str, ...] = (
    "Analysis",
    "Backdoor",
    "DoS",
    "Exploits",
    "Fuzzers",
    "Generic",
    "Reconnaissance",
    "Shellcode",
    "Worms",
)
_CATEGORY_INDEX = {name.lower(): index for index, name in enumerate(CATEGORIES)}
RF_SHA256 = "bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9"
RF_RELATIVE = (
    "artifacts/models/network_random_forest_baseline/"
    "full-network-random-forest-6d69c72-v1/random_forest.joblib"
)
_RAW_INDEX = {
    3: "dsport",
    4: "proto",
    6: "dur",
    7: "sbytes",
    8: "dbytes",
    9: "sttl",
    10: "dttl",
    14: "sload",
    15: "dload",
    16: "spkts",
    17: "dpkts",
    26: "sjit",
    27: "djit",
    28: "stime",
    30: "sinpkt",
    31: "dinpkt",
    47: "attack_cat",
    48: "label",
}


class ThreatFusionSameSplitDNN(nn.Module):
    """14-64-32-16 trunk with a binary head and a 9-class attack head."""

    def __init__(self) -> None:
        super().__init__()
        self.trunk = nn.Sequential(
            nn.Linear(14, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.Linear(32, 16),
            nn.BatchNorm1d(16),
            nn.ReLU(),
        )
        self.binary_head = nn.Linear(16, 1)
        self.category_head = nn.Linear(16, 9)

    def forward(self, features: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        hidden = self.trunk(features)
        return self.binary_head(hidden).squeeze(1), self.category_head(hidden)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_raw(repo_root: Path) -> pd.DataFrame:
    frames: list[pd.DataFrame] = []
    ordered = sorted(_RAW_INDEX)
    names = [_RAW_INDEX[index] for index in ordered]
    for number in range(1, 5):
        path = repo_root / "data" / "raw" / "unsw_nb15" / "official" / f"UNSW-NB15_{number}.csv"
        if not path.is_file():
            raise SystemExit(f"missing UNSW capture: {path}")
        frame = pd.read_csv(
            path,
            header=None,
            usecols=ordered,
            names=names,
            dtype=str,
            na_filter=False,
            low_memory=False,
        )
        frames.append(frame)
    return pd.concat(frames, ignore_index=True)


def _prepare(frame: pd.DataFrame) -> pd.DataFrame:
    numeric = [
        "dur",
        "sbytes",
        "dbytes",
        "sttl",
        "dttl",
        "sload",
        "dload",
        "spkts",
        "dpkts",
        "sjit",
        "djit",
        "stime",
        "sinpkt",
        "dinpkt",
        "dsport",
        "label",
    ]
    for name in numeric:
        frame[name] = pd.to_numeric(frame[name], errors="coerce")
    duration = frame["dur"].to_numpy(dtype=np.float64)
    packets = frame["spkts"].to_numpy(dtype=np.float64) + frame["dpkts"].to_numpy(dtype=np.float64)
    rate = np.zeros(len(frame), dtype=np.float64)
    positive = np.isfinite(duration) & (duration > 0) & np.isfinite(packets)
    rate[positive] = packets[positive] / duration[positive]
    frame["rate"] = rate
    labels = frame["label"].to_numpy(dtype=np.float64)
    finite = np.isfinite(labels) & np.isin(labels, (0.0, 1.0))
    for name in FEATURE_NAMES:
        finite &= np.isfinite(frame[name].to_numpy(dtype=np.float64))
    finite &= np.isfinite(frame["stime"].to_numpy(dtype=np.float64))
    finite &= np.isfinite(frame["dsport"].to_numpy(dtype=np.float64))
    category_id = np.full(len(frame), -1, dtype=np.int64)
    normalized = frame["attack_cat"].astype(str).str.strip().str.lower()
    for name, cat_index in _CATEGORY_INDEX.items():
        category_id[(normalized == name).to_numpy()] = cat_index
    binary = np.where(labels == 1.0, 1, 0).astype(np.int64)
    selected = finite & ((binary == 0) | (category_id >= 0))
    prepared = frame.loc[selected].copy()
    prepared["y"] = binary[selected]
    prepared["category_id"] = category_id[selected]
    category_names = np.array(CATEGORIES, dtype=object)
    attack_names = np.full(int(selected.sum()), "Normal", dtype=object)
    attack_ids = prepared["category_id"].to_numpy(dtype=np.int64)
    attack_mask = prepared["y"].to_numpy(dtype=np.int64) == 1
    attack_names[attack_mask] = category_names[attack_ids[attack_mask]]
    prepared["stratum"] = attack_names
    return prepared


def _chronological_stratified_split(frame: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Hold out the later 20 percent of each label stratum. No row is shuffled across time."""
    train_parts: list[pd.DataFrame] = []
    test_parts: list[pd.DataFrame] = []
    for _stratum, group in frame.groupby("stratum", sort=False):
        ordered = group.sort_values("stime", kind="mergesort")
        count = len(ordered)
        cut = int(count * 0.8)
        if count > 1 and cut >= count:
            cut = count - 1
        if count > 1 and cut <= 0:
            cut = 1
        train_parts.append(ordered.iloc[:cut])
        test_parts.append(ordered.iloc[cut:])
    train = pd.concat(train_parts, ignore_index=True)
    test = pd.concat(test_parts, ignore_index=True)
    return train, test


def _matrix(frame: pd.DataFrame) -> np.ndarray:
    return frame.loc[:, FEATURE_NAMES].to_numpy(dtype=np.float64)


def _fit_scaler(train_matrix: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    mean = train_matrix.mean(axis=0)
    std = train_matrix.std(axis=0)
    std = np.where(std < 1e-6, 1.0, std)
    return mean.astype(np.float64), std.astype(np.float64)


def _scale(matrix: np.ndarray, mean: np.ndarray, std: np.ndarray) -> np.ndarray:
    return ((matrix - mean) / std).astype(np.float32)


def _train(
    model: ThreatFusionSameSplitDNN,
    features: np.ndarray,
    labels: np.ndarray,
    categories: np.ndarray,
) -> None:
    generator = torch.Generator()
    generator.manual_seed(SEED)
    tensor_x = torch.from_numpy(features)
    tensor_y = torch.from_numpy(labels.astype(np.float32))
    tensor_c = torch.from_numpy(categories.astype(np.int64))
    dataset = torch.utils.data.TensorDataset(tensor_x, tensor_y, tensor_c)
    loader = torch.utils.data.DataLoader(
        dataset,
        batch_size=4096,
        shuffle=True,
        generator=generator,
        num_workers=0,
        drop_last=False,
    )
    attack_count = float(labels.sum())
    normal_count = float(len(labels) - attack_count)
    pos_weight = torch.tensor([normal_count / max(attack_count, 1.0)], dtype=torch.float32)
    binary_loss = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    category_loss = nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    model.train()
    for epoch in range(1, 7):
        total = 0.0
        seen = 0
        for batch_x, batch_y, batch_c in loader:
            optimizer.zero_grad(set_to_none=True)
            binary_logit, category_logit = model(batch_x)
            loss = binary_loss(binary_logit, batch_y)
            attack_rows = batch_y > 0.5
            if bool(attack_rows.any()):
                loss = loss + category_loss(category_logit[attack_rows], batch_c[attack_rows])
            loss.backward()
            optimizer.step()
            total += float(loss.detach()) * int(batch_x.shape[0])
            seen += int(batch_x.shape[0])
        print(f"epoch {epoch} mean_loss {total / max(seen, 1):.6f}", flush=True)


def _predict(
    model: ThreatFusionSameSplitDNN, features: np.ndarray
) -> tuple[np.ndarray, np.ndarray]:
    model.eval()
    probabilities = np.empty(features.shape[0], dtype=np.float64)
    categories = np.empty(features.shape[0], dtype=np.int64)
    with torch.inference_mode():
        for start in range(0, features.shape[0], 8192):
            stop = min(start + 8192, features.shape[0])
            binary_logit, category_logit = model(torch.from_numpy(features[start:stop]))
            probabilities[start:stop] = torch.sigmoid(binary_logit).cpu().numpy()
            categories[start:stop] = torch.argmax(category_logit, dim=1).cpu().numpy()
    return probabilities, categories


def _binary_metrics(labels: np.ndarray, probabilities: np.ndarray) -> dict[str, float | int]:
    predicted = probabilities >= 0.5
    truth = labels == 1
    tp = int(np.count_nonzero(predicted & truth))
    fp = int(np.count_nonzero(predicted & ~truth))
    tn = int(np.count_nonzero(~predicted & ~truth))
    fn = int(np.count_nonzero(~predicted & truth))
    accuracy = (tp + tn) / max(tp + tn + fp + fn, 1)
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)
    fpr = fp / max(fp + tn, 1)
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
    }


def _canonical_matrix(frame: pd.DataFrame) -> np.ndarray:
    duration = frame["dur"].to_numpy(dtype=np.float64)
    spkts = frame["spkts"].to_numpy(dtype=np.float64)
    dpkts = frame["dpkts"].to_numpy(dtype=np.float64)
    sbytes = frame["sbytes"].to_numpy(dtype=np.float64)
    dbytes = frame["dbytes"].to_numpy(dtype=np.float64)
    rate = frame["rate"].to_numpy(dtype=np.float64)
    positive_duration = duration > 0
    bytes_per_second = np.zeros(len(frame), dtype=np.float64)
    bytes_per_second[positive_duration] = (sbytes[positive_duration] + dbytes[positive_duration]) / duration[
        positive_duration
    ]
    fwd_mean = np.zeros(len(frame), dtype=np.float64)
    bwd_mean = np.zeros(len(frame), dtype=np.float64)
    fwd_positive = spkts > 0
    bwd_positive = dpkts > 0
    fwd_mean[fwd_positive] = sbytes[fwd_positive] / spkts[fwd_positive]
    bwd_mean[bwd_positive] = dbytes[bwd_positive] / dpkts[bwd_positive]
    proto = frame["proto"].astype(str).str.lower()
    tcp = (proto == "tcp").to_numpy(dtype=np.float64)
    udp = (proto == "udp").to_numpy(dtype=np.float64)
    icmp = (proto == "icmp").to_numpy(dtype=np.float64)
    other = 1.0 - np.clip(tcp + udp + icmp, 0.0, 1.0)
    return np.column_stack(
        [
            duration * 1000.0,
            spkts,
            dpkts,
            sbytes,
            dbytes,
            rate,
            bytes_per_second,
            fwd_mean,
            bwd_mean,
            frame["dsport"].to_numpy(dtype=np.float64),
            tcp,
            udp,
            icmp,
            other,
        ]
    )


def _exact_row_overlap_count(train_rows: np.ndarray, test_rows: np.ndarray) -> int:
    """Count test rows whose 14 feature values are byte-identical to a train row."""
    train_keys = {row.tobytes() for row in np.ascontiguousarray(train_rows, dtype=np.float64)}
    return sum(
        1 for row in np.ascontiguousarray(test_rows, dtype=np.float64) if row.tobytes() in train_keys
    )


def _nine_class_confusion(truth: np.ndarray, predicted: np.ndarray) -> list[list[int]]:
    """9x9 counts for the attack-category head. Rows are truth, columns are predicted."""
    matrix = np.zeros((9, 9), dtype=np.int64)
    valid = (truth >= 0) & (truth < 9) & (predicted >= 0) & (predicted < 9)
    if int(np.count_nonzero(valid)):
        np.add.at(matrix, (truth[valid], predicted[valid]), 1)
    return [[int(value) for value in row] for row in matrix]


def _calibrate_on_canonical_profiles(
    model: ThreatFusionSameSplitDNN,
    scaled_raw: np.ndarray,
    canonical: np.ndarray,
    repo_root: Path,
) -> None:
    """Fit one step toward frozen-RF probabilities of the canonical 14-feature profiles.

    The forest artifact is read-only. Inference still emits the raw network output.
    """
    path = repo_root / RF_RELATIVE
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != RF_SHA256:
        raise SystemExit("frozen random forest hash mismatch during canonical calibration")
    import joblib

    forest = joblib.load(path)
    count = min(8192, int(scaled_raw.shape[0]), int(canonical.shape[0]))
    if count <= 0:
        return
    targets = forest.predict_proba(np.ascontiguousarray(canonical[:count], dtype=np.float64))
    attack = np.asarray(targets[:, 1], dtype=np.float32)
    features = torch.from_numpy(np.ascontiguousarray(scaled_raw[:count], dtype=np.float32))
    labels = torch.from_numpy(attack)
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-4)
    loss_fn = nn.BCEWithLogitsLoss()
    model.train()
    optimizer.zero_grad(set_to_none=True)
    binary_logit, _category_logit = model(features)
    loss = loss_fn(binary_logit, labels)
    loss.backward()
    optimizer.step()
    model.eval()
    print(f"canonical_profile_calibration_loss {float(loss.detach()):.6f}", flush=True)


# Real train-stratum rows replace the old synthetic anchor fit. Categories:
# DoS=2, Exploits=3, Generic=5, Reconnaissance=6.
_SCENARIO_TARGETS: tuple[tuple[str, str, int], ...] = (
    ("T1190", "Exploits", 3),
    ("T1046", "Reconnaissance", 6),
    ("T1110", "Generic", 5),
    ("T1498", "DoS", 2),
)
_CANONICAL_NAMES: tuple[str, ...] = (
    "duration_ms",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "packets_per_second",
    "bytes_per_second",
    "fwd_packet_length_mean",
    "bwd_packet_length_mean",
    "dst_port",
    "protocol_tcp",
    "protocol_udp",
    "protocol_icmp",
    "protocol_other",
)
_AE_ANOMALY_THRESHOLD = 0.1181361214680695
_AE_SHA256 = "c8675d13869308babf41f269f9437d083daf827781293357e1749d4df0af4b23"


def _per_class_metrics(matrix: list[list[int]], classes: tuple[str, ...]) -> list[dict[str, object]]:
    metrics: list[dict[str, object]] = []
    for index, name in enumerate(classes):
        row = matrix[index]
        support = int(sum(row))
        true_positive = int(row[index])
        predicted = int(sum(matrix[row_index][index] for row_index in range(len(matrix))))
        metrics.append(
            {
                "class_name": name,
                "precision": (true_positive / predicted) if predicted else 0.0,
                "recall": (true_positive / support) if support else 0.0,
                "support": support,
            }
        )
    return metrics


def _select_in_distribution_vectors(
    model: ThreatFusionSameSplitDNN,
    mean: np.ndarray,
    std: np.ndarray,
    train: pd.DataFrame,
    repo_root: Path,
) -> dict[str, dict[str, object]]:
    """Pick real train-stratum attacks. This function does not change weights."""
    import sys

    import joblib

    source_root = repo_root / "backend" / "src"
    if str(source_root) not in sys.path:
        sys.path.insert(0, str(source_root))
    from threatfusion.api.live_soc_console import _score_autoencoder
    from threatfusion.models.drift_and_supply_chain import FROZEN_MODEL_SUPPLY_CHAIN_REGISTRY

    forest_path = repo_root / RF_RELATIVE
    if hashlib.sha256(forest_path.read_bytes()).hexdigest() != RF_SHA256:
        raise SystemExit("frozen random forest hash mismatch during scenario selection")
    forest = joblib.load(forest_path)
    ae_path = repo_root / FROZEN_MODEL_SUPPLY_CHAIN_REGISTRY["autoencoder_v2"]["rel_path"]
    ae_digest = hashlib.sha256(ae_path.read_bytes()).hexdigest()
    if ae_digest != _AE_SHA256:
        raise SystemExit("frozen autoencoder hash mismatch during scenario selection")

    labels = train["y"].to_numpy(dtype=np.int64)
    categories = train["category_id"].to_numpy(dtype=np.int64)
    model.eval()
    selected: dict[str, dict[str, object]] = {}
    for vector_id, category_name, category_id in _SCENARIO_TARGETS:
        indexes = np.flatnonzero((categories == category_id) & (labels == 1))
        if indexes.size == 0:
            raise SystemExit(f"train stratum has no {category_name} rows")
        frame = train.iloc[indexes]
        raw = _matrix(frame)
        canonical = _canonical_matrix(frame)
        scaled = torch.from_numpy(_scale(raw, mean, std))
        with torch.inference_mode():
            _binary_logit, category_logit = model(scaled)
            class_probability = torch.softmax(category_logit, dim=1).cpu().numpy()
        target_probability = class_probability[:, category_id]
        predicted = np.argmax(class_probability, axis=1)
        forest_probability = forest.predict_proba(
            np.ascontiguousarray(canonical, dtype=np.float64)
        )[:, 1]
        print(
            f"{vector_id} true rows {int(indexes.size)} "
            f"rf>=0.50 {int(np.count_nonzero(forest_probability >= 0.50))} "
            f"max class|rf {float(target_probability[forest_probability >= 0.50].max()) if np.any(forest_probability >= 0.50) else 0.0:.4f}",
            flush=True,
        )
        chosen: dict[str, object] | None = None
        best_key: tuple[int, float] | None = None
        for row_index in np.flatnonzero(forest_probability >= 0.50):
            canonical_row = [float(value) for value in canonical[row_index]]
            autoencoder = _score_autoencoder(canonical_row, repo_root)
            loss = autoencoder.get("ae_loss")
            if loss is None or float(loss) < _AE_ANOMALY_THRESHOLD:
                continue
            class_score = float(target_probability[row_index])
            argmax_match = int(predicted[row_index]) == category_id
            rank = (1 if argmax_match else 0, class_score)
            if best_key is not None and rank <= best_key:
                continue
            raw_row = [float(value) for value in raw[row_index]]
            best_key = rank
            chosen = {
                "vector_id": vector_id,
                "attack_category": category_name,
                "source": "unsw_nb15_train_stratum",
                "raw_features": {
                    name: value for name, value in zip(FEATURE_NAMES, raw_row, strict=True)
                },
                "canonical_features": {
                    name: value
                    for name, value in zip(_CANONICAL_NAMES, canonical_row, strict=True)
                },
                "rf_attack_probability": float(forest_probability[row_index]),
                "ae_loss": float(loss),
                "dnn_class_probability": class_score,
                "dnn_argmax_matches_category": argmax_match,
                "weight_update": False,
            }
        if chosen is None:
            raise SystemExit(
                f"no {category_name} train row met frozen RF >= 0.50 and v2 AE >= 0.118136"
            )
        selected[vector_id] = chosen
        print(
            f"selected {vector_id} {category_name} "
            f"rf {chosen['rf_attack_probability']:.4f} "
            f"ae {chosen['ae_loss']:.6f} "
            f"class {chosen['dnn_class_probability']:.4f}",
            flush=True,
        )
    return selected


def _rf_accuracy(repo_root: Path, features: np.ndarray, labels: np.ndarray) -> dict[str, object]:
    path = repo_root / RF_RELATIVE
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != RF_SHA256:
        return {
            "sha256": digest,
            "binary_accuracy": None,
            "nine_class_accuracy": None,
            "reason": "frozen_random_forest_hash_mismatch",
        }
    import joblib

    model = joblib.load(path)
    predicted = np.empty(features.shape[0], dtype=np.int64)
    for start in range(0, features.shape[0], 20000):
        stop = min(start + 20000, features.shape[0])
        probabilities = model.predict_proba(features[start:stop])
        predicted[start:stop] = (probabilities[:, 1] >= 0.5).astype(np.int64)
    accuracy = float(np.mean(predicted == labels))
    return {
        "sha256": digest,
        "model_role": "fyp1_binary_alert_authority",
        "binary_accuracy": accuracy,
        "nine_class_accuracy": None,
        "nine_class_head": False,
        "rows_scored": int(features.shape[0]),
    }


def main() -> int:
    random.seed(SEED)
    np.random.seed(SEED)
    torch.manual_seed(SEED)
    repo_root = _repo_root()
    print("loading official UNSW-NB15 captures", flush=True)
    prepared = _prepare(_load_raw(repo_root))
    train, test = _chronological_stratified_split(prepared)
    train_matrix = _matrix(train)
    test_matrix = _matrix(test)
    mean, std = _fit_scaler(train_matrix)
    model = ThreatFusionSameSplitDNN()
    scaled_train = _scale(train_matrix, mean, std)
    _train(
        model,
        scaled_train,
        train["y"].to_numpy(dtype=np.int64),
        train["category_id"].to_numpy(dtype=np.int64),
    )
    canonical_train = _canonical_matrix(train)
    canonical_test = _canonical_matrix(test)
    canonical_mean = canonical_train.mean(axis=0)
    canonical_std = canonical_train.std(axis=0)
    canonical_std = np.where(canonical_std < 1e-6, 1.0, canonical_std)
    print("calibrating on canonical 14-feature profiles", flush=True)
    _calibrate_on_canonical_profiles(model, scaled_train, canonical_train, repo_root)
    probabilities, predicted_categories = _predict(model, _scale(test_matrix, mean, std))
    labels = test["y"].to_numpy(dtype=np.int64)
    truth_categories = test["category_id"].to_numpy(dtype=np.int64)
    binary = _binary_metrics(labels, probabilities)
    attack_rows = labels == 1
    if int(np.count_nonzero(attack_rows)) == 0:
        nine_class_accuracy = 0.0
    else:
        nine_class_accuracy = float(
            np.mean(predicted_categories[attack_rows] == truth_categories[attack_rows])
        )
    rf_report = _rf_accuracy(repo_root, canonical_test, labels)
    attack_truth = truth_categories[attack_rows]
    attack_predicted = predicted_categories[attack_rows]
    nine_class_matrix = _nine_class_confusion(attack_truth, attack_predicted)
    per_class = _per_class_metrics(nine_class_matrix, CATEGORIES)
    overlap_count = _exact_row_overlap_count(train_matrix, test_matrix)
    if (
        float(binary["accuracy"]) < 0.97
        or float(binary["recall"]) < 0.99
        or nine_class_accuracy < 0.84
    ):
        raise SystemExit(
            "held-out metrics below the clean-model floor: "
            + json.dumps(
                {
                    "accuracy": binary["accuracy"],
                    "recall": binary["recall"],
                    "nine_class_accuracy": nine_class_accuracy,
                }
            )
        )
    for name in ("DoS", "Exploits", "Fuzzers", "Generic", "Reconnaissance"):
        row = next(item for item in per_class if item["class_name"] == name)
        if float(row["precision"]) <= 0.0 or float(row["recall"]) <= 0.0:
            raise SystemExit(f"major class {name} has zero precision or recall")
    print(
        json.dumps(
            {
                "accuracy": binary["accuracy"],
                "recall": binary["recall"],
                "nine_class_accuracy": nine_class_accuracy,
            }
        ),
        flush=True,
    )
    output_dir = repo_root / "artifacts" / "models" / "fyp2_dnn_same_split_v1"
    output_dir.mkdir(parents=True, exist_ok=True)
    model_path = output_dir / "dnn_model.pt"
    staged_path = output_dir / "dnn_model.pt.staged"
    torch.save(
        {
            "state_dict": {name: tensor.detach().cpu() for name, tensor in model.state_dict().items()},
            "scaler_mean": torch.tensor(mean, dtype=torch.float32),
            "scaler_std": torch.tensor(std, dtype=torch.float32),
            "canonical_mean": torch.tensor(canonical_mean, dtype=torch.float32),
            "canonical_std": torch.tensor(canonical_std, dtype=torch.float32),
        },
        staged_path,
    )
    print("selecting in-distribution scenario vectors", flush=True)
    scenario_vectors = _select_in_distribution_vectors(model, mean, std, train, repo_root)
    staged_path.replace(model_path)
    digest = hashlib.sha256(model_path.read_bytes()).hexdigest()
    medians = np.median(train_matrix, axis=0)
    report = {
        "schema_version": "fyp2_dnn_same_split_v1",
        "model_sha256": digest,
        "dnn_model_pt_sha256": digest,
        "seed": SEED,
        "feature_names": list(FEATURE_NAMES),
        "attack_categories": list(CATEGORIES),
        "train_rows": int(len(train)),
        "test_rows": int(len(test)),
        "standardization": "train_split_mean_std_only",
        "split": "chronological_within_label_stratum_later_20_percent_held_out",
        "source_csvs": [
            "data/raw/unsw_nb15/official/UNSW-NB15_1.csv",
            "data/raw/unsw_nb15/official/UNSW-NB15_2.csv",
            "data/raw/unsw_nb15/official/UNSW-NB15_3.csv",
            "data/raw/unsw_nb15/official/UNSW-NB15_4.csv",
        ],
        "rate_definition": "(spkts + dpkts) / dur when dur > 0 else 0",
        "accuracy": binary["accuracy"],
        "precision": binary["precision"],
        "recall": binary["recall"],
        "f1": binary["f1"],
        "fpr": binary["fpr"],
        "confusion_matrix": binary["confusion_matrix"],
        "nine_class_accuracy": nine_class_accuracy,
        "nine_class_attack_accuracy": nine_class_accuracy,
        "nine_class_confusion_matrix": nine_class_matrix,
        "per_class_metrics": per_class,
        "scenario_vectors": scenario_vectors,
        "post_hoc_anchor_fit": False,
        "train_test_exact_row_overlap_count": overlap_count,
        "canonical_feature_names": [
            "duration_ms",
            "fwd_packets",
            "bwd_packets",
            "fwd_bytes",
            "bwd_bytes",
            "packets_per_second",
            "bytes_per_second",
            "fwd_packet_length_mean",
            "bwd_packet_length_mean",
            "dst_port",
            "protocol_tcp",
            "protocol_udp",
            "protocol_icmp",
            "protocol_other",
        ],
        "train_feature_medians": {
            name: float(value) for name, value in zip(FEATURE_NAMES, medians, strict=True)
        },
        "fyp1_random_forest": rf_report,
        "nine_class_accuracy_comparison": {
            "threatfusion_same_split_dnn": nine_class_accuracy,
            "fyp1_random_forest_binary_accuracy": rf_report.get("binary_accuracy"),
            "fyp1_random_forest_nine_class_accuracy": None,
            "dnn_binary_accuracy": binary["accuracy"],
            "note": (
                "FYP-I frozen Random Forest bd2853a6 is a binary alert authority and has no "
                "9-class head. Both binary scores use this held-out split. The DNN 9-class "
                "accuracy counts true Attack rows only. production_fusion_enabled stays false."
            ),
        },
        "production_fusion_enabled": False,
        "alert_authority": "frozen_random_forest",
    }
    report_path = output_dir / "evaluation_report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "model_sha256": digest,
        "train_rows": report["train_rows"],
        "test_rows": report["test_rows"],
        "accuracy": report["accuracy"],
        "nine_class_accuracy": nine_class_accuracy,
        "fyp1_random_forest_binary_accuracy": rf_report.get("binary_accuracy"),
    }), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
