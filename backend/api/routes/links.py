from fastapi import APIRouter, Response, status

from backend.api.deps import CurrentUser, DbSession
from backend.schemas.link import LinkCreate, LinkOut
from backend.services import link_service

router = APIRouter(tags=["links"])


@router.get("/networks/{network_id}/links", response_model=list[LinkOut])
def list_links(network_id: int, db: DbSession, _: CurrentUser):
    return [link_service.to_out(link) for link in link_service.list_links(db, network_id)]


@router.post("/networks/{network_id}/links", response_model=LinkOut, status_code=status.HTTP_201_CREATED)
def create_link(network_id: int, payload: LinkCreate, db: DbSession, _: CurrentUser):
    return link_service.to_out(link_service.create_link(db, network_id, payload))


@router.delete("/links/{link_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_link(link_id: int, db: DbSession, _: CurrentUser):
    link_service.delete_link(db, link_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
