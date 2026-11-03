"""Fixed-input oracle for compact external event sorting and bounded caches."""
import itertools
import json
import random
import unittest

from airroute_data.geo import event_stream


def simple_oracle(records):
    """Independent in-memory algorithm, deliberately no interning or SQL."""
    events = []
    for rid, (family, start, end, payload) in enumerate(records):
        # The external format is JSON, so the oracle compares JSON values too.
        value = json.loads(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        events.append((family, start, 1, rid, value))
        events.append((family, end + 1, -1, rid, None))
    events.sort(key=lambda value: value[:4])
    result = []
    for (family, point), rows in itertools.groupby(events, lambda value: value[:2]):
        result.append((family, point, [(row[3], row[2], row[4]) for row in rows]))
    return result


class EventSortTests(unittest.TestCase):
    def test_both_cache_evictions_preserve_every_record_and_boundary(self):
        # More than 32768 distinct descriptions evicts both the insertion intern
        # cache and, in sorted order, the decoded cache. Repeated old descriptions
        # must still retrieve their own durable payload IDs after either eviction.
        descriptions = [{"asn": i + 1, "source": "fixed-view", "origins": [i + 1]} for i in range(32772)]
        records = [(4, 100 + i * 3, 101 + i * 3, payload) for i, payload in enumerate(descriptions)]
        records.extend([
            (4, 99, 99, descriptions[1]),
            (4, 100, 101, descriptions[0]),
            (4, 1000000, 1000000, descriptions[0]),
            (4, 1000000, 1000001, descriptions[1]),
            (4, 2**32 - 1, 2**32 - 1, descriptions[-1]),
            (6, 0, 2**128 - 1, descriptions[0]),
            (6, 0, 0, descriptions[1]),
            (6, 2**128 - 1, 2**128 - 1, descriptions[-1]),
        ])
        expected = simple_oracle(records)
        with event_stream(iter(records)) as stream:
            actual = list(stream)
        self.assertEqual(actual, expected)
        self.assertEqual(sum(len(changes) for _, _, changes in actual), len(records) * 2)
        self.assertEqual(actual[-1][1], 2**128, "IPv6 end sentinel needs 129 bits")

    def test_reused_payload_flush_boundaries_and_end_before_start_order(self):
        repeated = {"source": "fixed-view", "origins": [64500, 64501], "tags": {"b": 2, "a": 1}}
        # Cross multiple 8192-event flush batches, then order most end/start
        # changes at shared points rather than their original insertion order.
        records = [(4, 1 + i % 5, 5 + i % 7, repeated) for i in range(9000)]
        records += [(6, 1, 1, {}), (6, 2, 2, {}), (4, 6, 6, {"different": True})]
        with event_stream(records) as stream:
            self.assertEqual(list(stream), simple_oracle(records))

    def test_deterministic_scrambled_dual_stack_inputs_match_oracle(self):
        randomizer = random.Random(20261103)
        records = []
        for index in range(2000):
            family = 4 if index % 3 else 6
            start = randomizer.randrange(0, 50000)
            end = start + randomizer.randrange(0, 64)
            records.append((family, start, end, {"source": index % 13, "origins": [index % 37]}))
        randomizer.shuffle(records)
        expected = simple_oracle(records)
        for _ in range(2):
            with event_stream(iter(records)) as stream:
                self.assertEqual(list(stream), expected)

    def test_invalid_interval_does_not_reach_sort_oracle(self):
        for record in [(4, -1, 0, {}), (4, 1, 0, {}), (4, 0, 2**32, {}), (6, 0, 2**128, {}), (5, 0, 0, {})]:
            with self.subTest(record=record), self.assertRaisesRegex(ValueError, "outside address family"):
                with event_stream([record]) as stream:
                    list(stream)
