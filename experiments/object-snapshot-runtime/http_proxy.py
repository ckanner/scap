"""The same closed, bounded HTTP observer used by the owner acceptance."""
from support import HERE, load

HTTPProxy = load('snapshot_owner_http', HERE.parent / 'object-owner-plan-runtime/http_proxy.py').HTTPProxy
