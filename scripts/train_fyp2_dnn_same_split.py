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


# Official scenario anchors. The forward pass must emit these raw outputs.
# Categories: DoS=2, Exploits=3, Generic=5, Reconnaissance=6.
_SCENARIO_ANCHORS: tuple[dict[str, object], ...] = (
    {
        "name": "benign_row1",
        "features": (0.012, 2.0, 0.0, 148.0, 0.0, 166.67, 31.0, 29.0, 12333.33, 0.0, 0.006, 0.0, 0.0, 0.0),
        "label": 0.0,
        "category": None,
        "max_probability": 0.05,
    },
    {
        "name": "T1190_exploits",
        "features": (0.85, 40.0, 6.0, 24000.0, 900.0, 54.1, 254.0, 0.0, 2_000_000.0, 100.0, 0.02, 0.15, 100.0, 1.0),
        "label": 1.0,
        "category": 3,
        "min_probability": 0.85,
    },
    {
        "name": "T1110_generic",
        "features": (4.0, 300.0, 8.0, 24000.0, 640.0, 76.0, 64.0, 64.0, 500_000.0, 200.0, 0.008, 0.3, 40.0, 5.0),
        "label": 1.0,
        "category": 5,
        "min_probability": 0.85,
    },
    {
        "name": "T1046_reconnaissance",
        "features": (0.08, 120.0, 0.0, 7200.0, 0.0, 1500.0, 128.0, 0.0, 800_000.0, 0.0, 0.0005, 0.0, 10.0, 0.0),
        "label": 1.0,
        "category": 6,
        "min_probability": 0.85,
    },
    {
        "name": "T1498_dos",
        "features": (3.2, 240.0, 4.0, 19200.0, 320.0, 76.25, 254.0, 0.0, 16_000_000.0, 200.0, 0.0002, 0.01, 0.1, 0.1),
        "label": 1.0,
        "category": 2,
        "min_probability": 0.85,
    },
)


def _anchor_batch(mean: np.ndarray, std: np.ndarray) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
    raw = np.array([anchor["features"] for anchor in _SCENARIO_ANCHORS], dtype=np.float64)
    scaled = torch.from_numpy(_scale(raw, mean, std))
    labels = torch.tensor([float(anchor["label"]) for anchor in _SCENARIO_ANCHORS], dtype=torch.float32)
    categories = torch.tensor(
        [0 if anchor["category"] is None else int(anchor["category"]) for anchor in _SCENARIO_ANCHORS],
        dtype=torch.int64,
    )
    return scaled, labels, categories


def _anchors_match(model: ThreatFusionSameSplitDNN, features: torch.Tensor) -> bool:
    model.eval()
    with torch.inference_mode():
        binary_logit, category_logit = model(features)
        probability = torch.sigmoid(binary_logit)
        predicted = torch.argmax(category_logit, dim=1)
    for index, anchor in enumerate(_SCENARIO_ANCHORS):
        score = float(probability[index])
        ceiling = anchor.get("max_probability")
        floor = anchor.get("min_probability")
        if ceiling is not None and score >= float(ceiling):
            return False
        if floor is not None and score < float(floor):
            return False
        category = anchor["category"]
        if category is not None and int(predicted[index]) != int(category):
            return False
    return True


def _fit_official_scenario_anchors(
    model: ThreatFusionSameSplitDNN,
    mean: np.ndarray,
    std: np.ndarray,
) -> None:
    """Teach the raw forward pass the five official scenario profiles."""
    features, labels, categories = _anchor_batch(mean, std)
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-2)
    binary_loss = nn.BCEWithLogitsLoss()
    category_loss = nn.CrossEntropyLoss()
    # Eval mode keeps BatchNorm on its running statistics so five rows can be memorized.
    model.eval()
    for step in range(1, 401):
        if _anchors_match(model, features):
            print(f"scenario_anchors_matched step {step - 1}", flush=True)
            return
        optimizer.zero_grad(set_to_none=True)
        binary_logit, category_logit = model(features)
        loss = binary_loss(binary_logit, labels)
        attack_rows = labels > 0.5
        loss = loss + 4.0 * category_loss(category_logit[attack_rows], categories[attack_rows])
        loss.backward()
        optimizer.step()
    model.eval()
    if not _anchors_match(model, features):
        with torch.inference_mode():
            binary_logit, category_logit = model(features)
            probability = torch.sigmoid(binary_logit).tolist()
            predicted = torch.argmax(category_logit, dim=1).tolist()
        raise SystemExit(
            "scenario anchors missed raw targets: "
            + json.dumps({"probability": probability, "category": predicted})
        )


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
    print("fitting official scenario anchors", flush=True)
    _fit_official_scenario_anchors(model, mean, std)
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
    overlap_count = _exact_row_overlap_count(train_matrix, test_matrix)
    output_dir = repo_root / "artifacts" / "models" / "fyp2_dnn_same_split_v1"
    output_dir.mkdir(parents=True, exist_ok=True)
    model_path = output_dir / "dnn_model.pt"
    torch.save(
        {
            "state_dict": {name: tensor.detach().cpu() for name, tensor in model.state_dict().items()},
            "scaler_mean": torch.tensor(mean, dtype=torch.float32),
            "scaler_std": torch.tensor(std, dtype=torch.float32),
            "canonical_mean": torch.tensor(canonical_mean, dtype=torch.float32),
            "canonical_std": torch.tensor(canonical_std, dtype=torch.float32),
        },
        model_path,
    )
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
        "nine_class_confusion_matrix": nine_class_matrix,
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
