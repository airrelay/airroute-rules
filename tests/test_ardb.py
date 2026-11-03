import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

from airroute_data.ardb import FormatError, read_database, read_group, write_database

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "golden"
GEO = {
    1: ["192.0.2.128/25", "192.0.2.0/25", "192.0.2.0/24", "2001:db8::/33", "2001:db8:8000::/33"],
    9: ["198.51.100.0/24"],
    16: [],
}
ASN = {64500: ["192.0.2.0/24", "2001:db8::/48"], 64501: ["192.0.2.0/24"], 4200000000: ["2001:db8:1::/64"]}


class ArdbTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "test.ardb"

    def test_geo_bytes_are_the_published_golden(self):
        info = write_database(self.path, "geo", GEO, allowed_geo_ids=[1, 9, 16])
        self.assertEqual(self.path.read_bytes(), (GOLDEN / "geo-v1.ardb").read_bytes())
        self.assertEqual(info["sha256"], hashlib.sha256(self.path.read_bytes()).hexdigest())
        groups = read_database(self.path, "geo", allowed_geo_ids=[1, 9, 16])
        self.assertEqual(groups, {1: ["192.0.2.0/24", "2001:db8::/32"], 9: ["198.51.100.0/24"], 16: []})

    def test_header_and_directory_are_literal_contract(self):
        write_database(self.path, "geo", GEO)
        raw = self.path.read_bytes()
        self.assertEqual(len(raw), 175)
        self.assertEqual(raw[:12], b"ARDBv001\x01\x00\x01\x00")
        self.assertEqual(raw[12:16], b"\x03\x00\x00\x00")
        self.assertEqual(raw[16:24], (64).to_bytes(8, "little"))
        self.assertEqual(raw[24:32], (148).to_bytes(8, "little"))
        self.assertEqual(raw[32:64], bytes(32))
        self.assertEqual(struct.unpack_from("<IQIQI", raw, 64), (1, 148, 1, 153, 1))
        self.assertEqual(struct.unpack_from("<IQIQI", raw, 92), (9, 170, 1, 0, 0))
        self.assertEqual(struct.unpack_from("<IQIQI", raw, 120), (16, 0, 0, 0, 0))
        self.assertEqual(raw[148:153], bytes([192, 0, 2, 0, 24]))

    def test_asn_moas_cross_group_duplicates_and_empty_families(self):
        write_database(self.path, "asn", ASN)
        self.assertEqual(self.path.read_bytes(), (GOLDEN / "asn-v1.ardb").read_bytes())
        self.assertEqual(read_database(self.path, "asn"), {64500: ["192.0.2.0/24", "2001:db8::/48"], 64501: ["192.0.2.0/24"], 4200000000: ["2001:db8:1::/64"]})
        raw = self.path.read_bytes()
        a = struct.unpack_from("<IQIQI", raw, 64)
        b = struct.unpack_from("<IQIQI", raw, 92)
        self.assertNotEqual(a[1], b[1], "MOAS payloads are separate blocks, not aliasing offsets")

    def test_input_order_and_duplicate_invariance(self):
        write_database(self.path, "asn", ASN)
        before = self.path.read_bytes()
        write_database(self.path, "asn", {k: list(reversed(v + v)) for k, v in reversed(list(ASN.items()))})
        self.assertEqual(before, self.path.read_bytes())

    def test_empty_database(self):
        write_database(self.path, "asn", {})
        self.assertEqual(self.path.stat().st_size, 64)
        self.assertEqual(read_database(self.path, "asn"), {})

    def test_unknown_geo_group_and_unknown_requested_group_fail(self):
        write_database(self.path, "geo", GEO)
        with self.assertRaisesRegex(FormatError, "unknown Geo"):
            read_database(self.path, "geo", allowed_geo_ids=[1, 16])
        with self.assertRaisesRegex(FormatError, "unknown Geo"):
            write_database(self.path, "geo", GEO, allowed_geo_ids=[1, 16])
        with self.assertRaisesRegex(FormatError, "not present"):
            read_group(self.path, "geo", 42)

    def test_zero_negative_bool_and_out_of_u32_groups_rejected(self):
        for group in (0, -1, True, 1 << 32):
            with self.subTest(group=group), self.assertRaises(FormatError):
                write_database(self.path, "asn", {group: []})

    def test_invalid_kind_and_network_rejected(self):
        for kind in (True, 0, 3, 1.0, "mmdb"):
            with self.subTest(kind=kind), self.assertRaises(FormatError):
                write_database(self.path, kind, {})
        with self.assertRaises(FormatError):
            write_database(self.path, "asn", {1: ["not-a-network"]})

    def test_corrupt_goldens_all_fail_strict_python_validation(self):
        entries = json.loads((GOLDEN / "manifest.json").read_text())
        for case in entries["corrupt"]:
            with self.subTest(case=case["file"]), self.assertRaises(FormatError):
                read_database(GOLDEN / case["file"], case["kind"], allowed_geo_ids=[1, 9, 16])

    def test_symlink_rejected(self):
        self.path.symlink_to(GOLDEN / "geo-v1.ardb")
        with self.assertRaisesRegex(FormatError, "regular"):
            read_database(self.path, "geo")

    def test_truncated_files_and_offsets_never_allocate_from_hostile_counts(self):
        raw = bytearray((GOLDEN / "geo-v1.ardb").read_bytes())
        for pos, value, fmt in [(12, 0xffffffff, "<I"), (64 + 12, 0xffffffff, "<I"), (64 + 4, (1 << 64)-1, "<Q")]:
            bad = bytearray(raw)
            struct.pack_into(fmt, bad, pos, value)
            self.path.write_bytes(bad)
            with self.subTest(pos=pos), self.assertRaises(FormatError):
                read_database(self.path, "geo")
        for length in (0, 1, 63, 64, 147, 174):
            self.path.write_bytes(raw[:length])
            with self.subTest(length=length), self.assertRaises(FormatError):
                read_database(self.path, "geo")

    def test_unmerged_or_overlapping_records_rejected(self):
        # Hand-authored noncanonical output, not writer output: adjacent /25s.
        raw = struct.pack("<8sHBBIQQ32s", b"ARDBv001", 1, 2, 0, 1, 64, 92, bytes(32))
        raw += struct.pack("<IQIQI", 64500, 92, 2, 0, 0)
        raw += ipaddress.ip_address("192.0.2.0").packed + bytes([25])
        raw += ipaddress.ip_address("192.0.2.128").packed + bytes([25])
        self.path.write_bytes(raw)
        with self.assertRaisesRegex(FormatError, "mergeable"):
            read_database(self.path, "asn")


class CoreReaderInterop(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = os.environ.get("AIRROUTE_CORE_IP_DATA")
        if not source:
            raise unittest.SkipTest("set AIRROUTE_CORE_IP_DATA to actual Core crates/ip-data/src/lib.rs for cross-repo interop")
        source = Path(source).resolve()
        if not source.is_file() or not shutil.which("rustc"):
            raise unittest.SkipTest("actual Core source and rustc required")
        cls.temp = tempfile.TemporaryDirectory()
        directory = Path(cls.temp.name)
        cls.library = directory / "libairroute_ip_data.rlib"
        cls.binary = directory / "verify-ardb"
        subprocess.run(["rustc", "--edition=2024", "--crate-name", "airroute_ip_data", "--crate-type=rlib", str(source), "-o", str(cls.library)], check=True, capture_output=True)
        subprocess.run(["rustc", "--edition=2024", str(ROOT / "tools" / "verify_ardb.rs"), "--extern", "airroute_ip_data=" + str(cls.library), "-o", str(cls.binary)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "temp"):
            cls.temp.cleanup()

    def test_actual_core_reads_both_python_goldens(self):
        for name, kind, groups in [("geo-v1.ardb", "geo", {1: ["192.0.2.0/24", "2001:db8::/32"], 9: ["198.51.100.0/24"], 16: []}), ("asn-v1.ardb", "asn", ASN)]:
            ids = ",".join(map(str, sorted(groups)))
            result = subprocess.run([str(self.binary), kind, str(GOLDEN / name), ids], capture_output=True, text=True, check=True)
            expected = "".join(str(key) + "\t" + ",".join(groups[key]) + "\n" for key in sorted(groups))
            self.assertEqual(result.stdout, expected)

    def test_geo_registry_check_is_a_separate_client_installation_boundary(self):
        # Numeric ID 17 is structurally valid. The raw Core format reader has
        # no registry baked into it; the installation wrapper must supply one.
        path = GOLDEN / "corrupt-unknown-geo.ardb"
        rejected = subprocess.run([str(self.binary), "geo", str(path), "1,9,16"], capture_output=True, text=True)
        self.assertNotEqual(rejected.returncode, 0)
        structurally_valid = subprocess.run([str(self.binary), "geo", str(path), "1,9,17"], capture_output=True, text=True)
        self.assertEqual(structurally_valid.returncode, 0)
        self.assertIn("17\t\n", structurally_valid.stdout)

    def test_actual_core_rejects_common_corrupt_samples(self):
        manifest = json.loads((GOLDEN / "manifest.json").read_text())
        for case in manifest["corrupt"]:
            if not case["core_rejects"]:
                continue
            with self.subTest(case=case["file"]):
                result = subprocess.run([str(self.binary), case["kind"], str(GOLDEN / case["file"]), "1,9,16"], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
