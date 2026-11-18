"""Engineer B source-pinned synthetic security probes, private InvisiMark PR1.

PASS here means the observed behavior matched the expected forensic observation,
NOT that a security requirement passed. Source owner A must remediate findings.
No real photographs, live capture hooks, external keys, or network telemetry.
"""
from __future__ import annotations
import base64
import binascii
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import struct
import sys
import types
import zlib

import pytest
from PIL import Image

ROOT=Path(os.environ.get("INVISIMARK_B_AUDIT_ROOT",str(Path(__file__).resolve().parents[2])))
SOURCE=Path(os.environ.get("INVISIMARK_B_POC_SOURCE",str(ROOT/"prototype"/"invisimark_capsule.py")))
sys.path.insert(0,str(SOURCE.parent))
import invisimark_capsule as target

EXPECTED_BLOB="6c7d318e8c7d0df9442c5c2967bae1988549f337"
PASSWORD="synthetic-fixture-not-a-secret"


def png_bytes():
    f=io.BytesIO()
    Image.new("RGB",(16,16),(40,80,170)).save(f,format="PNG")
    return f.getvalue()


def packet_with_header(**overrides):
    header={
      "version":1,"alg":"AES-256-GCM","kdf":"scrypt-16384-8-1",
      "media":"image/png",
      "salt":base64.b64encode(b"S"*16).decode("ascii"),
      "nonce":base64.b64encode(b"N"*12).decode("ascii"),
    }
    header.update(overrides)
    data=json.dumps(header,sort_keys=True,separators=(",",":")).encode("ascii")
    return target.MAGIC + struct.pack(">I",len(data)) + data + b"Z"*16


def test_00_pinned_source_git_blob():
    b=SOURCE.read_bytes()
    git_sha=hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()
    assert git_sha==EXPECTED_BLOB


def test_01_authenticated_synthetic_roundtrip():
    original=png_bytes()
    packet=target.seal(original,PASSWORD)
    assert target.unseal(packet,PASSWORD)==original
    assert original not in packet
    assert packet.startswith(target.MAGIC)


@pytest.mark.parametrize("case",["wrong-password","ciphertext-tamper","header-tamper","truncated","missing-magic","oversize"])
def test_02_invalid_ciphertexts_do_not_release_bytes(case):
    pkt=target.seal(png_bytes(),PASSWORD)
    pw=PASSWORD
    if case=="wrong-password":pw="WRONG"
    elif case=="ciphertext-tamper":pkt=pkt[:-1]+bytes([pkt[-1]^1])
    elif case=="header-tamper":pkt=pkt[:20]+bytes([pkt[20]^1])+pkt[21:]
    elif case=="truncated":pkt=pkt[:-1]
    elif case=="missing-magic":pkt=b"X"+pkt[1:]
    else:pkt+=b"A"*(target.MAX_CAPSULE+1)
    with pytest.raises(target.CapsuleError):
        target.unseal(pkt,pw)


@pytest.mark.parametrize("part",["salt","nonce"])
def test_03_untrusted_header_invalid_base64_is_normalized(part):
    pkt=packet_with_header(**{part:"%%%INVALID%%%"})
    with pytest.raises(target.CapsuleError):
        target.unseal(pkt,PASSWORD)
    # Adversarial hypothesis FALSIFIED: binascii.Error derives from ValueError and is normalized.


def test_04_malformed_header_length_fails_closed():
    bad=target.MAGIC + struct.pack(">I",target.MAX_HEADER+1) + b"x"*20
    with pytest.raises(target.CapsuleError):
        target.unseal(bad,PASSWORD)


def test_05_non_json_header_fails_closed():
    hdr=b"not-json"
    pkt=target.MAGIC+struct.pack(">I",len(hdr))+hdr+b"0"*16
    with pytest.raises(target.CapsuleError):
        target.unseal(pkt,PASSWORD)


def test_06_malformed_png_with_magic_accepted_by_seal_and_unseal():
    pseudo_png=target.PNG_MAGIC+b"intentionally-invalid-png"
    pkt=target.seal(pseudo_png,PASSWORD)
    assert target.unseal(pkt,PASSWORD)==pseudo_png
    with pytest.raises(Exception):
        Image.open(io.BytesIO(pseudo_png)).verify()
    # Source capsule accepts signature, but viewer rejects full decode later.


def test_07_one_character_passphrase_accepted_without_policy():
    pkt=target.seal(png_bytes(),"x")
    assert target.unseal(pkt,"x")==png_bytes()
    # One character is valid for source; no strong-passphrase check exists.


def test_08_replay_of_same_capsule_remains_authorized():
    pkt=target.seal(png_bytes(),PASSWORD)
    assert target.unseal(pkt,PASSWORD)==target.unseal(pkt,PASSWORD)
    # Deliberate property: no revocation/replay or recipient binding in POC.


class FakeRoot:
    def __init__(self):self.labels=[]
    def title(self,*_):pass
    def configure(self,**_):pass
    def mainloop(self):pass

class FakeLabel:
    messages=[]
    def __init__(self,root,**kwargs):
        self.text=kwargs.get("text","")
        self.messages.append(self.text)
    def pack(self,**_):pass


def fake_gui(monkeypatch):
    FakeLabel.messages=[]
    fake=types.ModuleType("tkinter")
    fake.Tk=FakeRoot
    fake.Label=FakeLabel
    monkeypatch.setitem(sys.modules,"tkinter",fake)
    # Force a clean module import to ensure the tkinter ref resolves to fake.
    monkeypatch.delitem(sys.modules,"PIL.ImageTk",raising=False)


def test_09_verify_wrong_password_exit_status_two(tmp_path,monkeypatch,capsys):
    pkt=target.seal(png_bytes(),PASSWORD)
    p=tmp_path/"synthetic.ivmk"
    p.write_bytes(pkt)
    monkeypatch.setattr(target.getpass,"getpass",lambda *_:"wrong password")
    status=target.main(["verify",str(p)])
    cap=capsys.readouterr()
    assert status==2
    assert "Failed:" in cap.err
    assert "Authenticated" not in cap.out


def test_10_view_wrong_password_shows_error_but_returns_success(tmp_path,monkeypatch):
    pkt=target.seal(png_bytes(),PASSWORD)
    p=tmp_path/"synthetic.ivmk"
    p.write_bytes(pkt)
    fake_gui(monkeypatch)
    monkeypatch.setattr(target.getpass,"getpass",lambda *_:"wrong password")
    status=target.main(["view",str(p)])
    assert status==0
    assert "INTEGRITY OR AUTHORIZATION FAILURE" in FakeLabel.messages
    # This confirms an inconsistent observed CLI failure status.


def test_11_failed_image_size_limit_applied_after_load(monkeypatch):
    fake_gui(monkeypatch)
    events=[]
    class GiantImage:
        width=10000
        height=10000
        def verify(self):events.append("verify")
        def load(self):events.append("load")
        def thumbnail(self,*_):events.append("thumbnail")
    monkeypatch.setattr(Image,"open",lambda *_: GiantImage())
    malformed=target.seal(target.PNG_MAGIC+b"test",PASSWORD)
    target.show_capsule(malformed,PASSWORD)
    assert events==["verify","load"]
    assert "INTEGRITY OR AUTHORIZATION FAILURE" in FakeLabel.messages
    # This is a simulated oversized decode; no large real allocation performed.


def test_12_pack_keeps_original_plaintext_file(tmp_path,monkeypatch,capsys):
    b=png_bytes()
    source=tmp_path/"original.png"
    dest=tmp_path/"original.ivmk"
    source.write_bytes(b)
    monkeypatch.setattr(target.getpass,"getpass",lambda *_:PASSWORD)
    status=target.main(["pack",str(source),str(dest)])
    out=capsys.readouterr().out
    assert status==0
    assert source.read_bytes()==b
    assert dest.exists()
    assert "original image is not deleted" in out
    assert target.unseal(dest.read_bytes(),PASSWORD)==b


def test_13_pack_does_not_overwrite_existing_capsule(tmp_path,monkeypatch):
    source=tmp_path/"source.png"
    dest=tmp_path/"existing.ivmk"
    source.write_bytes(png_bytes())
    dest.write_bytes(b"SENTINEL")
    monkeypatch.setattr(target.getpass,"getpass",lambda *_:PASSWORD)
    assert target.main(["pack",str(source),str(dest)])==2
    assert dest.read_bytes()==b"SENTINEL"


def test_14_authorized_recipient_can_extract_plaintext_from_api():
    # Intentional limitation: authenticated plaintext is returned as ordinary bytes.
    picture=png_bytes()
    packet=target.seal(picture,PASSWORD)
    returned=target.unseal(packet,PASSWORD)
    assert isinstance(returned,bytes)
    assert returned==picture


def test_15_header_unknown_key_stays_rejected():
    packet=packet_with_header(rogue_key="recipient-foo")
    with pytest.raises(target.CapsuleError):
        target.unseal(packet,PASSWORD)


def test_16_no_automatic_passphrase_rate_limit():
    pkt=target.seal(png_bytes(),PASSWORD)
    for pw in ("a","b","c"):
        with pytest.raises(target.CapsuleError):
            target.unseal(pkt,pw)
    assert target.unseal(pkt,PASSWORD)==png_bytes()
    # This tests lack of stateful lockout, not practical key-cracking feasibility.


def test_17_cli_verify_does_not_export_original(tmp_path,monkeypatch):
    p=tmp_path/"one.ivmk"
    p.write_bytes(target.seal(png_bytes(),PASSWORD))
    monkeypatch.setattr(target.getpass,"getpass",lambda *_:PASSWORD)
    assert target.main(["verify",str(p)])==0
    assert [x.name for x in tmp_path.iterdir()]==["one.ivmk"]

def tiny_png_decompression_bomb():
    # A 69-byte synthetic PNG claiming 300M pixels; no enormous raster allocation.
    def chunk(tag,data):
        return struct.pack(">I",len(data))+tag+data+struct.pack(">I",zlib.crc32(tag+data)&0xffffffff)
    ihdr=struct.pack(">IIBBBBB",30000,10000,8,2,0,0,0)
    return target.PNG_MAGIC+chunk(b"IHDR",ihdr)+chunk(b"IDAT",zlib.compress(bytes(4)))+chunk(b"IEND",b"")


def test_18_tiny_compressed_oversized_image_escapes_viewer_failure_ui(monkeypatch):
    pseudo_png=tiny_png_decompression_bomb()
    assert len(pseudo_png)<120
    with pytest.raises(Image.DecompressionBombError):
        Image.open(io.BytesIO(pseudo_png))
    pkt=target.seal(pseudo_png,PASSWORD)
    assert target.unseal(pkt,PASSWORD)==pseudo_png
    fake_gui(monkeypatch)
    with pytest.raises(Image.DecompressionBombError):
        target.show_capsule(pkt,PASSWORD)
    assert FakeLabel.messages==[]
    # Real format parsing rejection occurs before any huge pixel allocation.


def test_19_cli_view_tiny_decompression_bomb_exception_uncaught(tmp_path,monkeypatch):
    pkt=target.seal(tiny_png_decompression_bomb(),PASSWORD)
    p=tmp_path/"declared_huge.ivmk"
    p.write_bytes(pkt)
    fake_gui(monkeypatch)
    monkeypatch.setattr(target.getpass,"getpass",lambda *_:PASSWORD)
    with pytest.raises(Image.DecompressionBombError):
        target.main(["view",str(p)])
