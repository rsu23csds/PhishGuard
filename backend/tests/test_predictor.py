from app.services.predictor import predict


def test_known_phishing_url():
    result = predict("url", "http://paypal-secure-login.tk/webscr?cmd=_login")
    assert result["verdict"] == "phishing"
    assert result["confidence"] >= 0.5
    assert result["explanations"]


def test_known_legit_url():
    result = predict("url", "https://www.wikipedia.org/wiki/Phishing")
    assert result["verdict"] == "legitimate"
