"""Scam types and verdicts, with labels in English, Hindi and Bengali."""

SCAM_TYPES = [
    "investment", "digital_arrest", "bank_kyc", "fake_payment", "fake_job",
    "family_emergency", "parcel", "bill_challan", "other",
]
VERDICTS = ["scam", "unsure", "no_signs"]
LANGS = ["en", "hi", "bn"]

TYPE_LABELS = {
    "investment": {"en": "Investment, trading or task scam", "hi": "निवेश, ट्रेडिंग या टास्क स्कैम", "bn": "বিনিয়োগ, ট্রেডিং বা টাস্ক স্ক্যাম"},
    "digital_arrest": {"en": "Digital arrest: fake police or officials", "hi": "डिजिटल अरेस्ट: नकली पुलिस या अधिकारी", "bn": "ডিজিটাল অ্যারেস্ট: ভুয়ো পুলিশ বা অফিসার"},
    "bank_kyc": {"en": "Fake bank, KYC or card message", "hi": "नकली बैंक, KYC या कार्ड संदेश", "bn": "ভুয়ো ব্যাংক, KYC বা কার্ডের বার্তা"},
    "fake_payment": {"en": "Fake payment, refund or 'sent by mistake'", "hi": "नकली पेमेंट, रिफंड या 'गलती से भेजे पैसे'", "bn": "ভুয়ো পেমেন্ট, রিফান্ড বা 'ভুল করে পাঠানো টাকা'"},
    "fake_job": {"en": "Fake job or work-from-home offer", "hi": "नकली नौकरी या वर्क-फ्रॉम-होम ऑफर", "bn": "ভুয়ো চাকরি বা ঘরে বসে কাজের অফার"},
    "family_emergency": {"en": "Family emergency or voice-clone call", "hi": "परिवार की इमरजेंसी या नकली आवाज़ वाला कॉल", "bn": "পরিবারের বিপদ বা নকল গলার কল"},
    "parcel": {"en": "Courier or customs parcel scam", "hi": "कूरियर या कस्टम पार्सल स्कैम", "bn": "কুরিয়ার বা কাস্টমস পার্সেল স্ক্যাম"},
    "bill_challan": {"en": "Bill, e-challan or service cut-off threat", "hi": "बिल, ई-चालान या कनेक्शन काटने की धमकी", "bn": "বিল, ই-চালান বা সংযোগ কাটার হুমকি"},
    "other": {"en": "Other suspicious message", "hi": "अन्य संदिग्ध संदेश", "bn": "অন্য সন্দেহজনক বার্তা"},
}

VERDICT_LABELS = {
    "scam": {"en": "Likely scam", "hi": "संभवतः स्कैम", "bn": "সম্ভবত স্ক্যাম"},
    "unsure": {"en": "Can't tell. Verify it yourself", "hi": "पक्का नहीं कह सकते। खुद जाँचें", "bn": "নিশ্চিত বলা যাচ্ছে না। নিজে যাচাই করুন"},
    "no_signs": {"en": "No scam signs found", "hi": "स्कैम के कोई संकेत नहीं मिले", "bn": "স্ক্যামের কোনো লক্ষণ পাওয়া যায়নি"},
}

HEADLINES = {
    "scam": {"en": "This looks like a scam.", "hi": "यह स्कैम लगता है।", "bn": "এটা স্ক্যাম বলে মনে হচ্ছে।"},
    "unsure": {"en": "We can't be sure. Here's how to check safely.", "hi": "हम पक्का नहीं कह सकते। सुरक्षित तरीके से ऐसे जाँचें।", "bn": "আমরা নিশ্চিত নই। নিরাপদে এভাবে যাচাই করুন।"},
    "no_signs": {"en": "We found no common scam signs. That isn't a guarantee.", "hi": "हमें स्कैम के आम संकेत नहीं मिले। यह कोई गारंटी नहीं है।", "bn": "আমরা স্ক্যামের সাধারণ লক্ষণ পাইনি। এটা কোনো গ্যারান্টি নয়।"},
}
