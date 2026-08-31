from threatfusion.datasets.adapters.mordor import adapt_mordor_row


def test_mordor_process_event_maps_to_host_event() -> None:
    event = adapt_mordor_row(
        {
            "RecordID": "1001",
            "UtcTime": "2026-01-01T12:00:00Z",
            "Computer": "win10-lab",
            "User": "LAB\\bilal",
            "EventID": "1",
            "ProviderName": "Microsoft-Windows-Sysmon",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "ParentImage": "C:\\Windows\\explorer.exe",
            "CommandLine": "powershell.exe -NoProfile -EncodedCommand AAAA",
            "TechniqueID": "T1059.001",
            "label": "attack",
        }
    )

    assert event.source_dataset == "mordor"
    assert event.schema_version == "host_event_v1"
    assert event.event_type == "process"
    assert event.host == "win10-lab"
    assert event.user == "LAB\\bilal"
    assert event.mitre_attack_id == "T1059.001"
    assert event.label == "attack"


def test_mordor_network_event_preserves_endpoint_context() -> None:
    event = adapt_mordor_row(
        {
            "EventRecordID": "2002",
            "@timestamp": "2026-01-01T12:01:00Z",
            "Computer": "win10-lab",
            "EventID": "3",
            "Image": "C:\\Windows\\System32\\curl.exe",
            "SourceIp": "192.168.1.20",
            "DestinationIp": "10.0.0.9",
            "DestinationPort": "443",
            "TechniqueID": "T1105",
        }
    )

    assert event.event_type == "network"
    assert event.process_name == "C:\\Windows\\System32\\curl.exe"
    assert event.src_ip == "192.168.1.20"
    assert event.dst_ip == "10.0.0.9"
    assert event.dst_port == 443
    assert event.mitre_attack_id == "T1105"


def test_mordor_authentication_event_is_classified() -> None:
    event = adapt_mordor_row(
        {
            "event_id": "auth-1",
            "timestamp": "2026-01-01T12:02:00Z",
            "host": "dc01",
            "TargetUserName": "administrator",
            "EventID": "4625",
            "Channel": "Security",
            "label": "failed_login",
        }
    )

    assert event.event_type == "authentication"
    assert event.user == "administrator"
    assert event.provider == "Security"
