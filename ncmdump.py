#!/usr/bin/env python3
"""Simple NCM to MP3/FLAC converter in Python.

This is a Python reimplementation of the C++ `ncmdump` tool. It is
based on code released under the MIT license.
"""

import argparse
import base64
import json
import os
import struct
from pathlib import Path

from Crypto.Cipher import AES
from mutagen.flac import FLAC, Picture
from mutagen.id3 import APIC, ID3, TALB, TIT2, TPE1

CORE_KEY = bytes(
    [0x68, 0x7A, 0x48, 0x52, 0x41, 0x6D, 0x73, 0x6F,
     0x35, 0x6B, 0x49, 0x6E, 0x62, 0x61, 0x78, 0x57])
MODIFY_KEY = bytes(
    [0x23, 0x31, 0x34, 0x6C, 0x6A, 0x6B, 0x5F, 0x21,
     0x5C, 0x5D, 0x26, 0x30, 0x55, 0x3C, 0x27, 0x28])
PNG_MAGIC = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])


def aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(data)
    pad = decrypted[-1]
    if pad <= 16:
        decrypted = decrypted[:-pad]
    return decrypted


class NeteaseMusicMetadata:
    def __init__(self, raw: dict | None):
        raw = raw or {}
        self.name = raw.get("musicName", "")
        self.album = raw.get("album", "")
        self.artist = ""
        for a in raw.get("artist", []):
            if isinstance(a, list) and a:
                if self.artist:
                    self.artist += "/"
                self.artist += str(a[0])
        self.format = raw.get("format", "")
        self.duration = raw.get("duration", 0)
        self.bitrate = raw.get("bitrate", 0)


class NeteaseCrypt:
    def __init__(self, path: str):
        self.filepath = Path(path)
        self.dump_filepath: Path | None = None
        self.format: str | None = None
        self.image_data = b""
        self.key_box = [0] * 256
        self.metadata: NeteaseMusicMetadata | None = None

        self.file = open(path, "rb")
        if not self._is_ncm_file():
            raise ValueError("Not netease protected file")
        self.file.seek(2, os.SEEK_CUR)
        self._parse_keys()
        self._parse_meta()
        self._parse_image()

    def _is_ncm_file(self) -> bool:
        return self.file.read(8) == b"CTENFDAM"

    def _read_int(self) -> int:
        data = self.file.read(4)
        if len(data) != 4:
            raise ValueError("Unexpected EOF")
        return struct.unpack("<I", data)[0]

    def _parse_keys(self) -> None:
        key_len = self._read_int()
        key_data = bytearray(self.file.read(key_len))
        for i in range(len(key_data)):
            key_data[i] ^= 0x64
        m_key_data = aes_ecb_decrypt(CORE_KEY, bytes(key_data))
        self._build_key_box(m_key_data[17:])

    def _parse_meta(self) -> None:
        meta_len = self._read_int()
        if meta_len <= 0:
            self.file.seek(abs(meta_len), os.SEEK_CUR)
            return
        meta_data = bytearray(self.file.read(meta_len))
        for i in range(len(meta_data)):
            meta_data[i] ^= 0x63
        decoded = base64.b64decode(meta_data[22:])
        decrypted = aes_ecb_decrypt(MODIFY_KEY, decoded)
        if decrypted.startswith(b"music:"):
            decrypted = decrypted[6:]
        self.metadata = NeteaseMusicMetadata(json.loads(decrypted.decode("utf-8")))

    def _parse_image(self) -> None:
        self.file.seek(5, os.SEEK_CUR)
        cover_frame_len = self._read_int()
        img_len = self._read_int()
        if img_len > 0:
            self.image_data = self.file.read(img_len)
        else:
            self.image_data = b""
        self.file.seek(cover_frame_len - img_len, os.SEEK_CUR)

    def _build_key_box(self, key: bytes) -> None:
        key_len = len(key)
        last_byte = 0
        key_offset = 0
        for i in range(256):
            self.key_box[i] = i
        for i in range(256):
            swap = self.key_box[i]
            c = (swap + last_byte + key[key_offset]) & 0xFF
            key_offset = (key_offset + 1) % key_len
            self.key_box[i] = self.key_box[c]
            self.key_box[c] = swap
            last_byte = c

    def dump(self, output_dir: str | None) -> None:
        out_path = self.filepath
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            out_path = Path(output_dir) / self.filepath.name
        buffer_size = 0x8000
        output = None
        while True:
            chunk = self.file.read(buffer_size)
            if not chunk:
                break
            chunk = bytearray(chunk)
            for i in range(len(chunk)):
                j = (i + 1) & 0xFF
                chunk[i] ^= self.key_box[(self.key_box[j] + self.key_box[(self.key_box[j] + j) & 0xFF]) & 0xFF]
            if output is None:
                if chunk[:3] == b"ID3":
                    out_path = out_path.with_suffix(".mp3")
                    self.format = "mp3"
                else:
                    out_path = out_path.with_suffix(".flac")
                    self.format = "flac"
                output = open(out_path, "wb")
                self.dump_filepath = out_path
            output.write(chunk)
        if output:
            output.close()

    def fix_metadata(self) -> None:
        if not self.dump_filepath or not self.metadata:
            return
        if self.format == "mp3":
            audio = ID3(str(self.dump_filepath))
            audio.delall("APIC")
            audio.add(TIT2(encoding=3, text=self.metadata.name))
            audio.add(TALB(encoding=3, text=self.metadata.album))
            audio.add(TPE1(encoding=3, text=self.metadata.artist))
            if self.image_data:
                mime = "image/png" if self.image_data.startswith(PNG_MAGIC) else "image/jpeg"
                audio.add(APIC(encoding=3, mime=mime, type=3, desc="Cover", data=self.image_data))
            audio.save()
        elif self.format == "flac":
            audio = FLAC(str(self.dump_filepath))
            audio["title"] = self.metadata.name
            audio["album"] = self.metadata.album
            audio["artist"] = self.metadata.artist
            if self.image_data:
                pic = Picture()
                pic.data = self.image_data
                pic.type = 3
                pic.mime = "image/png" if self.image_data.startswith(PNG_MAGIC) else "image/jpeg"
                audio.clear_pictures()
                audio.add_picture(pic)
            audio.save()


def process_file(path: Path, output_dir: Path | None) -> None:
    try:
        crypt = NeteaseCrypt(str(path))
        crypt.dump(str(output_dir) if output_dir else None)
        crypt.fix_metadata()
        print(f"[Done] '{path}' -> '{crypt.dump_filepath}'")
    except Exception as exc:
        print(f"[Error] {exc} '{path}'")


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert NCM files")
    parser.add_argument("files", nargs="*", help="Input files")
    parser.add_argument("-d", "--directory", help="Process folder")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursive mode")
    parser.add_argument("-o", "--output", help="Output folder")
    args = parser.parse_args()

    output = Path(args.output) if args.output else None

    if args.directory:
        source = Path(args.directory)
        entries = source.rglob("*.ncm") if args.recursive else source.glob("*.ncm")
        for entry in entries:
            dest = output / entry.relative_to(source).parent if output else entry.parent
            process_file(entry, dest)
    for f in args.files:
        path = Path(f)
        if path.is_file() and path.suffix == ".ncm":
            process_file(path, output or path.parent)


if __name__ == "__main__":
    main()
