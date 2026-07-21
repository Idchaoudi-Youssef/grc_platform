"""API tests for asset CRUD operations and validation rules."""


def sample_asset(ip_address: str = "192.0.2.10") -> dict:
    return {
        "name": "Public web server",
        "ip_address": ip_address,
        "asset_type": "server",
        "owner": "Infrastructure Team",
        "business_criticality": 5,
        "exposure": "external",
        "description": "Customer-facing service",
    }


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_create_and_read_ipv4_asset(client):
    create_response = client.post("/assets", json=sample_asset())
    assert create_response.status_code == 201
    created = create_response.json()
    assert created["id"] == 1
    assert created["ip_address"] == "192.0.2.10"
    assert created["asset_type"] == "server"
    assert created["owner"] == "Infrastructure Team"

    read_response = client.get("/assets/1")
    assert read_response.status_code == 200
    assert read_response.json()["name"] == "Public web server"


def test_create_ipv6_asset(client):
    response = client.post("/assets", json=sample_asset("2001:db8::10"))
    assert response.status_code == 201
    assert response.json()["ip_address"] == "2001:db8::10"


def test_list_assets(client):
    client.post("/assets", json=sample_asset("10.0.0.1"))
    client.post("/assets", json=sample_asset("10.0.0.2"))
    response = client.get("/assets")
    assert response.status_code == 200
    assert len(response.json()) == 2


def test_update_asset(client):
    client.post("/assets", json=sample_asset())
    response = client.patch(
        "/assets/1",
        json={"business_criticality": 3, "exposure": "internal"},
    )
    assert response.status_code == 200
    assert response.json()["business_criticality"] == 3
    assert response.json()["exposure"] == "internal"


def test_accepts_each_valid_asset_type(client):
    valid_types = [
        "server",
        "workstation",
        "network_device",
        "application",
        "database",
        "other",
    ]
    for index, asset_type in enumerate(valid_types, start=1):
        asset = sample_asset(f"192.0.2.{index}")
        asset["asset_type"] = asset_type
        response = client.post("/assets", json=asset)
        assert response.status_code == 201
        assert response.json()["asset_type"] == asset_type


def test_rejects_missing_asset_type(client):
    asset = sample_asset()
    del asset["asset_type"]
    response = client.post("/assets", json=asset)
    assert response.status_code == 422


def test_rejects_missing_owner(client):
    asset = sample_asset()
    del asset["owner"]
    response = client.post("/assets", json=asset)
    assert response.status_code == 422


def test_creates_asset_with_owner(client):
    response = client.post("/assets", json=sample_asset())
    assert response.status_code == 201
    assert response.json()["owner"] == "Infrastructure Team"


def test_updates_owner(client):
    client.post("/assets", json=sample_asset())
    response = client.patch("/assets/1", json={"owner": "SOC Team"})
    assert response.status_code == 200
    assert response.json()["owner"] == "SOC Team"


def test_updates_asset_type(client):
    client.post("/assets", json=sample_asset())
    response = client.patch("/assets/1", json={"asset_type": "application"})
    assert response.status_code == 200
    assert response.json()["asset_type"] == "application"


def test_partial_update_preserves_omitted_fields(client):
    created = client.post("/assets", json=sample_asset()).json()
    response = client.patch("/assets/1", json={"owner": "SOC Team"})
    assert response.status_code == 200
    updated = response.json()
    assert updated["owner"] == "SOC Team"
    assert updated["name"] == created["name"]
    assert updated["ip_address"] == created["ip_address"]
    assert updated["asset_type"] == created["asset_type"]
    assert updated["business_criticality"] == created["business_criticality"]
    assert updated["exposure"] == created["exposure"]


def test_delete_asset(client):
    client.post("/assets", json=sample_asset())
    assert client.delete("/assets/1").status_code == 204
    assert client.get("/assets/1").status_code == 404


def test_rejects_invalid_ip_address(client):
    response = client.post("/assets", json=sample_asset("not-an-ip"))
    assert response.status_code == 422


def test_rejects_criticality_outside_one_to_five(client):
    asset = sample_asset()
    asset["business_criticality"] = 6
    response = client.post("/assets", json=asset)
    assert response.status_code == 422


def test_rejects_unknown_exposure(client):
    asset = sample_asset()
    asset["exposure"] = "partner"
    response = client.post("/assets", json=asset)
    assert response.status_code == 422


def test_rejects_unknown_asset_type(client):
    asset = sample_asset()
    asset["asset_type"] = "container"
    response = client.post("/assets", json=asset)
    assert response.status_code == 422


def test_rejects_blank_owner(client):
    asset = sample_asset()
    asset["owner"] = "   "
    response = client.post("/assets", json=asset)
    assert response.status_code == 422


def test_rejects_null_for_required_field_during_update(client):
    client.post("/assets", json=sample_asset())
    response = client.patch("/assets/1", json={"name": None})
    assert response.status_code == 422


def test_rejects_duplicate_ip_address(client):
    assert client.post("/assets", json=sample_asset()).status_code == 201
    response = client.post("/assets", json=sample_asset())
    assert response.status_code == 409


def test_missing_asset_returns_not_found(client):
    assert client.get("/assets/999").status_code == 404
    assert client.patch("/assets/999", json={"name": "New name"}).status_code == 404
    assert client.delete("/assets/999").status_code == 404
