from fastapi import APIRouter, Response, status
from pydantic import BaseModel, Field

from backend.api.deps import CurrentUser, DbSession
from backend.schemas.network import (NETWORK_TYPES, ImportResult, NetworkCreate, NetworkImport, NetworkOut,
                                     NetworkUpdate)
from backend.schemas.topology import PositionsSaved, PositionsUpdate, TopologyOut
from backend.services import config_import, demo_topology, import_sample, network_service, topology_service

router = APIRouter(prefix="/networks", tags=["networks"])


@router.get("", response_model=list[NetworkOut])
def list_networks(db: DbSession, _: CurrentUser):
    return network_service.to_out_many(db, network_service.list_networks(db))


@router.get("/types", response_model=list[str])
def network_types(_: CurrentUser):
    return list(NETWORK_TYPES)


@router.post("", response_model=NetworkOut, status_code=status.HTTP_201_CREATED)
def create_network(payload: NetworkCreate, db: DbSession, user: CurrentUser):
    return network_service.to_out(db, network_service.create_network(db, payload, user))


@router.post("/demo", response_model=NetworkOut, status_code=status.HTTP_201_CREATED)
def create_demo_network(db: DbSession, user: CurrentUser, faulty: bool = False):
    """Create the brief's demo topology. faulty=true injects errors for the Health Check demo."""
    return network_service.to_out(db, demo_topology.create_demo_network(db, user, faulty=faulty))


@router.post("/import", response_model=ImportResult)
def import_network(payload: NetworkImport, db: DbSession, user: CurrentUser):
    """Build a network from Cisco IOS show output; dry_run=true only previews what would be created."""
    return config_import.import_network(db, user, payload.name, payload.configs, payload.endpoints,
                                        payload.flows, payload.dry_run)


class ProjectFile(BaseModel):
    name: str = Field(max_length=255)
    content: str  # base64


class ProjectImport(BaseModel):
    name: str | None = Field(default=None, max_length=100)
    files: list[ProjectFile] = Field(min_length=1, max_length=200)


@router.post("/import-project", status_code=status.HTTP_201_CREATED)
def import_project(payload: ProjectImport, db: DbSession, user: CurrentUser):
    """Packet Tracer, GNS3 and EVE-NG project files, or a bundle of device configurations."""
    from backend.services import project_import
    files = project_import.decode_files([f.model_dump() for f in payload.files])
    return project_import.import_project(db, user, files, payload.name)


@router.post("/{network_id}/infer-neighbours")
def infer_neighbours(network_id: int, db: DbSession, user: CurrentUser):
    from backend.services import project_import
    network = network_service.get_network(db, network_id)
    result = project_import.infer_neighbours(db, user, network)
    result["inferred_flows"] = project_import.infer_intents(db, network)
    return result


@router.get("/import/sample")
def import_sample_input(_: CurrentUser):
    return {"name": "HQ Network (imported)", "configs": import_sample.CONFIGS,
            "endpoints": import_sample.ENDPOINTS, "flows": import_sample.FLOWS}


@router.get("/{network_id}", response_model=NetworkOut)
def get_network(network_id: int, db: DbSession, _: CurrentUser):
    return network_service.to_out(db, network_service.get_network(db, network_id))


@router.put("/{network_id}", response_model=NetworkOut)
def update_network(network_id: int, payload: NetworkUpdate, db: DbSession, _: CurrentUser):
    return network_service.to_out(db, network_service.update_network(db, network_id, payload))


@router.delete("/{network_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_network(network_id: int, db: DbSession, user: CurrentUser):
    network_service.delete_network(db, network_id, user)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{network_id}/topology", response_model=TopologyOut)
def get_topology(network_id: int, db: DbSession, _: CurrentUser):
    return topology_service.get_topology(db, network_id)


@router.put("/{network_id}/topology/positions", response_model=PositionsSaved)
def save_positions(network_id: int, payload: PositionsUpdate, db: DbSession, _: CurrentUser):
    return PositionsSaved(updated=topology_service.save_positions(db, network_id, payload.positions))
