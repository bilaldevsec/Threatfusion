from threatfusion.datasets.adapters.cic_ids2018 import adapt_cic_row
from threatfusion.datasets.adapters.unsw_nb15 import adapt_unsw_row


def test_unsw_adapter_maps_only_semantic_common_features() -> None:
    flow = adapt_unsw_row(
        {
            "id": "1",
            "stime": "1704110400",
            "srcip": "192.168.1.10",
            "dstip": "10.0.0.5",
            "sport": "49152",
            "dsport": "443",
            "proto": "tcp",
            "dur": "2.0",
            "spkts": "10",
            "dpkts": "8",
            "sbytes": "1200",
            "dbytes": "900",
            "label": "1",
            "attack_cat": "Exploits",
        }
    )

    assert flow.source_dataset == "unsw_nb15"
    assert flow.duration_ms == 2000.0
    assert flow.fwd_packets == 10
    assert flow.bwd_packets == 8
    assert flow.fwd_bytes == 1200
    assert flow.bwd_bytes == 900
    assert flow.protocol == "tcp"
    assert flow.label == "Attack"
    assert flow.attack_category == "Exploits"


def test_cic_adapter_converts_microseconds_to_milliseconds() -> None:
    flow = adapt_cic_row(
        {
            "Flow ID": "flow-a",
            "Timestamp": "14/02/2018 08:31:01",
            "Src IP": "172.31.69.25",
            "Dst IP": "18.219.211.138",
            "Src Port": "51524",
            "Dst Port": "22",
            "Protocol": "6",
            "Flow Duration": "3000000",
            "Tot Fwd Pkts": "12",
            "Tot Bwd Pkts": "10",
            "TotLen Fwd Pkts": "1400",
            "TotLen Bwd Pkts": "1800",
            "Label": "SSH-Bruteforce",
        }
    )

    assert flow.source_dataset == "cse_cic_ids2018"
    assert flow.duration_ms == 3000.0
    assert flow.fwd_packets == 12
    assert flow.bwd_packets == 10
    assert flow.fwd_bytes == 1400
    assert flow.bwd_bytes == 1800
    assert flow.protocol == "tcp"
    assert flow.label == "Attack"
    assert flow.attack_category == "SSH-Bruteforce"


def test_cic_benign_label_becomes_normal() -> None:
    flow = adapt_cic_row(
        {
            "Flow ID": "flow-benign",
            "Timestamp": "14/02/2018 08:31:01",
            "Src IP": "172.31.69.25",
            "Dst IP": "18.219.211.138",
            "Src Port": "51524",
            "Dst Port": "80",
            "Protocol": "6",
            "Flow Duration": "1000000",
            "Tot Fwd Pkts": "5",
            "Tot Bwd Pkts": "5",
            "TotLen Fwd Pkts": "500",
            "TotLen Bwd Pkts": "700",
            "Label": "Benign",
        }
    )

    assert flow.label == "Normal"
    assert flow.attack_category is None
