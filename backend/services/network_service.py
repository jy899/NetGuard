from __future__ import annotations

from sqlalchemy import event, func, select
from sqlalchemy.orm import Session, object_session

from backend.core.errors import ConflictError, ForbiddenError, NotFoundError
from backend.models import Device, Link, Network, User
from backend.schemas.network import NetworkCreate, NetworkOut, NetworkUpdate


def get_network(db: Session, network_id: int) -> Network:
    network = db.get(Network, network_id)
    if network is None:
        raise NotFoundError(f"Network {network_id} not found")
    return network


def _ensure_unique_name(db: Session, name: str, exclude_id: int | None = None) -> None:
    query = select(Network.id).where(func.lower(Network.name) == name.lower())
    if exclude_id is not None:
        query = query.where(Network.id != exclude_id)
    if db.scalar(query) is not None:
        raise ConflictError(f"A network named '{name}' already exists")


def _counts(db: Session, network_ids: list[int]) -> tuple[dict[int, int], dict[int, int]]:
    if not network_ids:
        return {}, {}
    device_counts = dict(
        db.execute(
            select(Device.network_id, func.count(Device.id))
            .where(Device.network_id.in_(network_ids))
            .group_by(Device.network_id)
        ).all()
    )
    link_counts = dict(
        db.execute(
            select(Link.network_id, func.count(Link.id))
            .where(Link.network_id.in_(network_ids))
            .group_by(Link.network_id)
        ).all()
    )
    return device_counts, link_counts


def to_out(db: Session, network: Network) -> NetworkOut:
    return to_out_many(db, [network])[0]


def to_out_many(db: Session, networks: list[Network]) -> list[NetworkOut]:
    device_counts, link_counts = _counts(db, [n.id for n in networks])
    results = []
    for network in networks:
        out = NetworkOut.model_validate(network)
        out.created_by_username = network.creator.username if network.creator else None
        out.device_count = device_counts.get(network.id, 0)
        out.link_count = link_counts.get(network.id, 0)
        results.append(out)
    return results


def list_networks(db: Session) -> list[Network]:
    return list(db.scalars(select(Network).order_by(Network.updated_at.desc(), Network.id.desc())))


def create_network(db: Session, data: NetworkCreate, user: User | None) -> Network:
    _ensure_unique_name(db, data.name)
    network = Network(**data.model_dump(), created_by=user.id if user else None)
    db.add(network)
    db.commit()
    db.refresh(network)
    return network


def update_network(db: Session, network_id: int, data: NetworkUpdate) -> Network:
    network = get_network(db, network_id)
    _ensure_unique_name(db, data.name, exclude_id=network_id)
    for key, value in data.model_dump(exclude_unset=True).items():
        setattr(network, key, value)
    db.commit()
    db.refresh(network)
    return network


def delete_network(db: Session, network_id: int, user: User | None = None) -> None:
    network = get_network(db, network_id)
    if user is not None:
        from backend.services.credential_service import can_manage
        if not can_manage(user, network):
            raise ForbiddenError("Only the network's owner or an administrator can delete this network.")
    db.delete(network)
    db.commit()
    from backend.database.init_db import purge_orphans
    purge_orphans()  # independent of foreign-key enforcement: no device, link or flow outlives its network


def touch(network: Network) -> None:
    """Mark a network as modified (used when its topology changes)."""
    network.updated_at = func.now()
    if network.source == "discovery" and (network.metadata_json or {}).get("method") == "smart":
        # Discovery status describes the current model. Reclassify just before this transaction commits, after
        # every edit in it (some services touch the network before deleting or adding rows).
        session = object_session(network)
        if session is not None:
            session.info.setdefault("ng_reclassify", set()).add(network.id)


@event.listens_for(Session, "before_commit")
def _reclassify_discoveries(session: Session) -> None:
    pending = session.info.pop("ng_reclassify", None)
    if not pending:
        return
    from backend.services.discovery import classification, service
    session.flush()  # sessions use autoflush=False; classification must see this transaction's edits
    for network_id in pending:
        network = session.get(Network, network_id)
        if network is not None:
            classification.classify(session, network)  # model edits never re-run fusion
            service._sync_login_ids(network)
