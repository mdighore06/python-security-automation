from ml.threat_detector import load_and_preprocess_data

def test_load_and_preprocess_data():
    X, y = load_and_preprocess_data()
    assert not X.empty
    assert len(X) == len(y)
