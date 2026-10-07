"""Language detection, masking and link extraction."""
from checker import lang, masking
from checker.text_utils import is_official, upi_ids, urls


def test_detect_scripts_and_romanised():
    assert lang.detect("आपका बिजली बिल जारी हो गया है") == "hi"
    assert lang.detect("আপনার বিদ্যুৎ বিল বকেয়া আছে") == "bn"
    assert lang.detect("Bhaiya main 8 baje tak pahunch jaunga, gate khula rakhna") == "hi-Latn"
    assert lang.detect("Didi kal sondhebela mamar barite jachhi, tumi ashbe?") == "bn-Latn"
    assert lang.detect("Your Amazon order has been shipped.") == "en"
    assert lang.base("bn-Latn") == "bn"


def test_mixed_script_message_follows_the_main_script():
    assert lang.detect("आपका OTP 482915 है, किसी के साथ साझा न करें। -ICICI बैंक") == "hi"


def test_masking_hides_personal_numbers():
    text = ("Card 4111 1111 1111 1111, Aadhaar 1234 5678 9012, call 9876543210, "
            "A/c 502001234567, OTP is 482915, PAN ABCDE1234F")
    masked, counts = masking.mask(text)
    for secret in ("4111", "9012", "9876543210", "502001234567", "482915", "ABCDE1234F"):
        assert secret not in masked
    assert "[CARD-NUMBER]" in masked and "[ID-NUMBER]" in masked and "[PHONE]" in masked
    assert "[OTP]" in masked and "[PAN]" in masked
    assert counts


def test_masking_keeps_links_amounts_and_upi_ids():
    text = "Pay ₹4,999 to profitking@ybl or visit sbi-kyc-update.xyz/a1234567890 now"
    masked, _ = masking.mask(text)
    assert "₹4,999" in masked
    assert "profitking@ybl" in masked
    assert "sbi-kyc-update.xyz/a1234567890" in masked


def test_masking_handles_otp_before_phrase_and_bengali_digits():
    masked, _ = masking.mask("123456 is your OTP for login. আপনার OTP ৭৩৮২১৯।")
    assert "123456" not in masked and "৭৩৮২১৯" not in masked


def test_url_extraction_and_official_hosts():
    found = dict(urls("Pay at wbsedcl.in-এ or echallan.parivahan.gov.in, not echallan-parivahan.co/pay. Mail a@b.com"))
    assert "wbsedcl.in" in found and "echallan.parivahan.gov.in" in found and "echallan-parivahan.co" in found
    assert "b.com" not in found
    assert is_official("echallan.parivahan.gov.in") and is_official("amzn.in") and not is_official("echallan-parivahan.co")


def test_upi_ids_are_not_emails():
    assert upi_ids("send to riya.helps@paytm") == [("riya.helps", "paytm")]
    assert upi_ids("mail me at someone@gmail.com") == []
