import httpx
import respx

from recon.models import HtmlData, ResourceRef
from recon.modules.javascript import AssetCollector, ChunkExtractor
from recon.utils.http_client import SafeHttpClient
from recon.utils.scope import Scope
from tests.conftest import public_resolve


# ------------------------------------------------------------------ pure extraction

def test_vite_mapdeps_assets_are_extracted():
    text = ('const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=['
            '"assets/profile-a1b2c3d4.js","assets/settings-e5f6a7b8.js"])))=>i.map(x=>d[x]);')
    urls = ChunkExtractor.extract(text, "https://app.test/assets/index-x.js")
    assert "https://app.test/assets/profile-a1b2c3d4.js" in urls
    assert "https://app.test/assets/settings-e5f6a7b8.js" in urls


def test_webpack_hashed_chunks_and_dynamic_imports():
    text = ('var x=__webpack_require__;a="static/js/42.8f3ab1cd.chunk.js";'
            'import("./lazy-deadbeef.js");')
    urls = ChunkExtractor.extract(text, "https://app.test/static/js/main.1234abcd.js")
    assert any(u.endswith("/static/js/42.8f3ab1cd.chunk.js") for u in urls)
    assert any(u.endswith("/static/js/lazy-deadbeef.js") for u in urls)


def test_no_chunks_without_bundler_markers():
    assert ChunkExtractor.extract('const a = "notachunk.js";', "https://app.test/x.js") == []


# ------------------------------------------------------------------ collector follows the chunk

def _clients():
    scope = Scope(roots=["app.test"], hosts=())
    kw = dict(user_agent="t", retries=0, resolve=public_resolve)
    return SafeHttpClient(scope, max_response_bytes=2_000_000, **kw), SafeHttpClient(scope, max_response_bytes=4096, **kw)


@respx.mock
async def test_collector_follows_lazy_chunk_and_analyses_it():
    # entry bundle references a Vite lazy chunk that is NOT linked from the HTML; its endpoint is only found
    # because the chunk is followed.
    entry = ('const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/admin-9a8b7c6d.js"])))=>i;')
    chunk = 'fetch("https://app.test/api/admin/secrets");'
    respx.get("https://app.test/assets/index-main.js").mock(return_value=httpx.Response(200, content=entry.encode()))
    respx.get("https://app.test/assets/admin-9a8b7c6d.js").mock(return_value=httpx.Response(200, content=chunk.encode()))
    html = HtmlData(source_url="https://app.test/", resources=[
        ResourceRef(url="https://app.test/assets/index-main.js", kind="script", host="app.test",
                    same_site=True, attributes={})])
    client, map_client = _clients()
    async with client, map_client:
        data, errors = await AssetCollector("app.test", client, map_client, html=html).collect()
    assert data.chunks_followed == 1
    urls = {a.url for a in data.assets}
    assert "https://app.test/assets/admin-9a8b7c6d.js" in urls
    # the endpoint that exists only in the lazy chunk is now inventoried
    assert any("/api/admin/secrets" in e.value for e in data.endpoints())
