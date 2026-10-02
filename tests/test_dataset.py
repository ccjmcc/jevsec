import csv
import hashlib
import json
from security_engine.dataset import BENIGN, generate_dataset

def test_generator_reproducible_shape(tmp_path):
    e,l=generate_dataset(tmp_path,entities=1200,seed=42)
    assert sum(1 for _ in e.open())>=10000
    assert sum(1 for _ in l.open())>=1001
    rows=list(csv.DictReader(l.open()))
    assert {row['scenario'] for row in rows if row['split']=='test' and row['category']=='benign'} == set(BENIGN)
    assert {row['scenario'] for row in rows if row['split']=='validation' and row['category']=='benign'} == set(BENIGN)
    manifest=json.loads((tmp_path/'dataset_manifest.json').read_text())
    assert manifest['generator_version'] == 2
    assert manifest['behavior_windows'] == 1200
    assert manifest['events_sha256'] == hashlib.sha256(e.read_bytes()).hexdigest()
    assert manifest['labels_sha256'] == hashlib.sha256(l.read_bytes()).hexdigest()
