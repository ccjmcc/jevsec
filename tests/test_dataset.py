from security_engine.dataset import generate_dataset

def test_generator_reproducible_shape(tmp_path):
    e,l=generate_dataset(tmp_path,entities=1200,seed=42)
    assert sum(1 for _ in e.open())>=10000
    assert sum(1 for _ in l.open())>=1001
