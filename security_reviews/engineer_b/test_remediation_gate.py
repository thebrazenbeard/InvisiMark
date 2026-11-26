"""Engineer B strict remediation gate for the source-compatible Windows viewer.

Default XFAIL documents two confirmed PR1 defects. Set
INVISIMARK_B_REQUIRE_FIXED=1 for a hard test (no expected failures).
This gate tests a synthetic fake Tk UI; not a real Windows screenshot path.
"""
from __future__ import annotations
import io,os,struct,sys,types,zlib
from pathlib import Path
import pytest
from PIL import Image

ROOT=Path(__file__).resolve().parents[2]
SOURCE=Path(os.environ.get("INVISIMARK_B_POC_SOURCE",str(ROOT/"prototype"/"invisimark_capsule.py")))
sys.path.insert(0,str(SOURCE.parent))
import invisimark_capsule as target

PASSWORD="synthetic-known-test-secret"
REQUIRE_FIXED=os.environ.get("INVISIMARK_B_REQUIRE_FIXED")=="1"
known_red=pytest.mark.xfail(not REQUIRE_FIXED,reason="observed PR1 defect; set REQUIRE_FIXED for candidate",strict=True)

def png():
    stream=io.BytesIO()
    Image.new("RGB",(16,16),(50,95,130)).save(stream,format="PNG")
    return stream.getvalue()

class FakeRoot:
    def title(self,*args):pass
    def configure(self,**kwargs):pass
    def mainloop(self):pass

class FakeLabel:
    messages=[]
    def __init__(self,root,**kwargs):self.messages.append(kwargs.get("text",""))
    def pack(self,**kwargs):pass

def fake_gui(monkeypatch):
    FakeLabel.messages=[]
    mod=types.ModuleType("tkinter")
    mod.Tk=FakeRoot
    mod.Label=FakeLabel
    monkeypatch.setitem(sys.modules,"tkinter",mod)
    monkeypatch.delitem(sys.modules,"PIL.ImageTk",raising=False)

def png_bomb_metadata():
    # This is a tiny 69-byte header test, NOT a large allocation.
    def chunk(kind,data):
        return struct.pack(">I",len(data))+kind+data+struct.pack(">I",zlib.crc32(kind+data)&0xffffffff)
    ihdr=struct.pack(">IIBBBBB",30000,10000,8,2,0,0,0)
    return target.PNG_MAGIC+chunk(b"IHDR",ihdr)+chunk(b"IDAT",zlib.compress(bytes(4)))+chunk(b"IEND",b"")

@known_red
def test_wrong_password_view_returns_nonzero_and_warning(tmp_path,monkeypatch):
    p=tmp_path/"fixture.ivmk"
    p.write_bytes(target.seal(png(),PASSWORD))
    fake_gui(monkeypatch)
    monkeypatch.setattr(target.getpass,"getpass",lambda *_:"WRONG")
    outcome=target.main(["view",str(p)])
    assert "INTEGRITY OR AUTHORIZATION FAILURE" in FakeLabel.messages
    assert isinstance(outcome,int) and outcome != 0

@known_red
def test_oversized_metadata_has_controlled_failure(tmp_path,monkeypatch):
    fake=png_bomb_metadata()
    assert len(fake)<120
    p=tmp_path/"oversized.ivmk"
    p.write_bytes(target.seal(fake,PASSWORD))
    fake_gui(monkeypatch)
    monkeypatch.setattr(target.getpass,"getpass",lambda *_:PASSWORD)
    outcome=target.main(["view",str(p)])
    assert "INTEGRITY OR AUTHORIZATION FAILURE" in FakeLabel.messages
    assert isinstance(outcome,int) and outcome != 0

def test_verify_wrong_password_nonzero_and_no_export(tmp_path,monkeypatch):
    p=tmp_path/"fixture.ivmk"
    p.write_bytes(target.seal(png(),PASSWORD))
    monkeypatch.setattr(target.getpass,"getpass",lambda *_:"WRONG")
    assert target.main(["verify",str(p)]) != 0
    assert [x.name for x in tmp_path.iterdir()]==["fixture.ivmk"]

def test_truncation_rejected():
    packet=target.seal(png(),PASSWORD)
    with pytest.raises(target.CapsuleError):
        target.unseal(packet[:-1],PASSWORD)

def test_roundtrip():
    original=png()
    assert target.unseal(target.seal(original,PASSWORD),PASSWORD)==original
