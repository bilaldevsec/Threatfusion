import json
from pathlib import Path

import pandas as pd

from threatfusion.datasets.adapters.cic_ids2018 import adapt_cic_row
from threatfusion.datasets.adapters.mordor import adapt_mordor_row
from threatfusion.datasets.adapters.unsw_nb15 import adapt_unsw_row
from threatfusion.datasets.parity import compare_network_flows
from threatfusion.schemas.flow import NetworkFlow

FIXTURES = Path(__file__).parents[1] / "fixtures"


def _load_csv_row(path: Path) -> dict[str, object]:
    return pd.read_csv(path).iloc[0].to_dict()


def test_network_fixtures_have_common_flow_parity() -> None:
    unsw_row = _load_csv_row(FIXTURES / "network" / "unsw_nb15_common_flow.csv")
    cic_row = _load_csv_row(FIXTURES / "network" / "cic_ids2018_common_flow.csv")

    unsw_flow = adapt_unsw_row(unsw_row)
    cic_flow = adapt_cic_row(cic_row)

    assert compare_network_flows(unsw_flow, cic_flow) == ()


def test_network_fixture_parity_reports_changed_backward_bytes() -> None:
    unsw_row = _load_csv_row(FIXTURES / "network" / "unsw_nb15_common_flow.csv")
    cic_row = _load_csv_row(FIXTURES / "network" / "cic_ids2018_common_flow.csv")
    cic_row["TotLen Bwd Pkts"] = 901

    mismatches = compare_network_flows(adapt_unsw_row(unsw_row), adapt_cic_row(cic_row))

    assert "bwd_bytes" in {mismatch.field for mismatch in mismatches}


def test_mordor_fixture_remains_a_host_event() -> None:
    fixture_path = FIXTURES / "host" / "mordor_process_event.json"
    row = json.loads(fixture_path.read_text(encoding="utf-8"))

    event = adapt_mordor_row(row)

    assert event.schema_version == "host_event_v1"
    assert event.source_dataset == "mordor"
    assert event.event_type == "process"
    assert event.mitre_attack_id == "T1059.001"
    assert not isinstance(event, NetworkFlow)
