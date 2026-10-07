"""Fixed advice text in English, Hindi and Bengali.

Next steps, verification tips and rule explanations are templates, not model output, so the
checker never invents a phone number, a link or an organisation.
"""
from .taxonomy import TYPE_LABELS, VERDICT_LABELS

NEXT_STEPS = {
    "scam": {
        "en": ["Don't pay, click any link, or share an OTP, UPI PIN or card details.",
               "Block the sender and report the message or call on Chakshu at sancharsaathi.gov.in.",
               "If you've already paid or shared details, call 1930 right away or report at cybercrime.gov.in."],
        "hi": ["पैसे न भेजें, किसी लिंक पर क्लिक न करें, और OTP, UPI पिन या कार्ड की जानकारी किसी को न दें।",
               "भेजने वाले को ब्लॉक करें और sancharsaathi.gov.in पर चक्षु में इस संदेश या कॉल की शिकायत करें।",
               "अगर आपने पैसे भेज दिए हैं या जानकारी दे दी है, तो तुरंत 1930 पर कॉल करें या cybercrime.gov.in पर शिकायत करें।"],
        "bn": ["টাকা পাঠাবেন না, কোনো লিঙ্কে ক্লিক করবেন না, আর OTP, UPI পিন বা কার্ডের তথ্য কাউকে দেবেন না।",
               "প্রেরককে ব্লক করুন এবং sancharsaathi.gov.in-এ চক্ষু-তে এই বার্তা বা কলের অভিযোগ জানান।",
               "যদি টাকা পাঠিয়ে থাকেন বা তথ্য দিয়ে থাকেন, এখনই ১৯৩০-এ ফোন করুন বা cybercrime.gov.in-এ অভিযোগ করুন।"],
    },
    "unsure": {
        "en": ["Don't act on this message yet: don't pay, click or reply.",
               "Check directly with the organisation through its official app, or a number you look up yourself. Never use a number or link from the message.",
               "Never share an OTP, UPI PIN or CVV, whoever asks."],
        "hi": ["अभी इस संदेश पर कुछ न करें: न पैसे भेजें, न लिंक खोलें, न जवाब दें।",
               "संस्था से सीधे उसकी आधिकारिक ऐप या खुद ढूंढे गए नंबर से पुष्टि करें। संदेश में दिया नंबर या लिंक कभी इस्तेमाल न करें।",
               "OTP, UPI पिन या CVV कभी किसी को न बताएं, चाहे कोई भी मांगे।"],
        "bn": ["এখনই এই বার্তা অনুযায়ী কিছু করবেন না: টাকা পাঠাবেন না, লিঙ্ক খুলবেন না, উত্তর দেবেন না।",
               "সংস্থার অফিসিয়াল অ্যাপ বা নিজে খুঁজে পাওয়া নম্বরে সরাসরি যাচাই করুন। বার্তায় দেওয়া নম্বর বা লিঙ্ক কখনও ব্যবহার করবেন না।",
               "OTP, UPI পিন বা CVV কখনও কাউকে বলবেন না, যে-ই চাক না কেন।"],
    },
    "no_signs": {
        "en": ["We found no common scam signs, but that isn't a guarantee.",
               "Never share an OTP, UPI PIN or CVV, whoever asks.",
               "If anything feels off later, check through the official app or call 1930 for help."],
        "hi": ["हमें स्कैम के आम संकेत नहीं मिले, लेकिन यह कोई गारंटी नहीं है।",
               "OTP, UPI पिन या CVV कभी किसी को न बताएं, चाहे कोई भी मांगे।",
               "बाद में कुछ भी अजीब लगे तो आधिकारिक ऐप से जाँचें या मदद के लिए 1930 पर कॉल करें।"],
        "bn": ["আমরা স্ক্যামের সাধারণ কোনো লক্ষণ পাইনি, তবে এটা কোনো গ্যারান্টি নয়।",
               "OTP, UPI পিন বা CVV কখনও কাউকে বলবেন না, যে-ই চাক না কেন।",
               "পরে কিছু অস্বাভাবিক লাগলে অফিসিয়াল অ্যাপে যাচাই করুন বা সাহায্যের জন্য ১৯৩০-এ ফোন করুন।"],
    },
}

VERIFY = {
    "investment": {"en": "Check any adviser on SEBI Check (siportal.sebi.gov.in/intermediary/sebi-check). Registered brokers collect money only through UPI IDs ending in @valid.",
                   "hi": "किसी भी सलाहकार को SEBI Check (siportal.sebi.gov.in/intermediary/sebi-check) पर जाँचें। पंजीकृत ब्रोकर सिर्फ @valid वाली UPI ID से पैसे लेते हैं।",
                   "bn": "যেকোনো উপদেষ্টাকে SEBI Check (siportal.sebi.gov.in/intermediary/sebi-check)-এ যাচাই করুন। রেজিস্টার্ড ব্রোকার শুধু @valid যুক্ত UPI ID-তে টাকা নেয়।"},
    "digital_arrest": {"en": "Police, CBI, customs or courts never arrest anyone on a video call or ask for money to 'verify' you. Hang up and call 1930.",
                       "hi": "पुलिस, सीबीआई, कस्टम या कोर्ट कभी वीडियो कॉल पर गिरफ्तारी नहीं करते और 'जांच' के लिए पैसे नहीं मांगते। कॉल काटें और 1930 पर बताएं।",
                       "bn": "পুলিশ, সিবিআই, কাস্টমস বা আদালত কখনও ভিডিও কলে গ্রেফতার করে না বা 'যাচাইয়ের' জন্য টাকা চায় না। ফোন কেটে ১৯৩০-এ জানান।"},
    "bank_kyc": {"en": "Open your bank's official app, or call the number on the back of your card. Banks never send links for KYC or ask for OTPs.",
                 "hi": "अपने बैंक की आधिकारिक ऐप खोलें या कार्ड के पीछे लिखे नंबर पर कॉल करें। बैंक KYC के लिए लिंक नहीं भेजते और OTP नहीं मांगते।",
                 "bn": "আপনার ব্যাংকের অফিসিয়াল অ্যাপ খুলুন বা কার্ডের পিছনে লেখা নম্বরে ফোন করুন। ব্যাংক KYC-র জন্য লিঙ্ক পাঠায় না এবং OTP চায় না।"},
    "fake_payment": {"en": "Check your own bank SMS or UPI app. A screenshot can never prove a payment, and you never need a PIN to receive money.",
                     "hi": "अपने बैंक का SMS या UPI ऐप खुद जाँचें। स्क्रीनशॉट से पेमेंट साबित नहीं होता, और पैसे पाने के लिए कभी पिन नहीं लगता।",
                     "bn": "নিজের ব্যাংকের SMS বা UPI অ্যাপ দেখুন। স্ক্রিনশট দিয়ে পেমেন্ট প্রমাণ হয় না, আর টাকা পেতে কখনও পিন লাগে না।"},
    "fake_job": {"en": "Real employers never charge a fee for a job, training or an offer letter. Check the company's careers page yourself.",
                 "hi": "असली कंपनियां नौकरी, ट्रेनिंग या ऑफर लेटर के लिए कभी फीस नहीं लेतीं। कंपनी की करियर वेबसाइट खुद देखें।",
                 "bn": "আসল কোম্পানি চাকরি, ট্রেনিং বা অফার লেটারের জন্য কখনও টাকা নেয় না। কোম্পানির ক্যারিয়ার পেজ নিজে দেখুন।"},
    "family_emergency": {"en": "Hang up and call the person back on the number you already have, or ask a question only they would know.",
                         "hi": "कॉल काटें और उस व्यक्ति को उसके पुराने, जाने-पहचाने नंबर पर खुद कॉल करें, या ऐसा सवाल पूछें जिसका जवाब सिर्फ वही जानता हो।",
                         "bn": "ফোন কেটে মানুষটিকে তাঁর পুরোনো, চেনা নম্বরে নিজে ফোন করুন, বা এমন প্রশ্ন করুন যার উত্তর শুধু তিনিই জানেন।"},
    "parcel": {"en": "Track parcels only on the courier's official website or app. Couriers don't ask for fees through links.",
               "hi": "पार्सल सिर्फ कूरियर कंपनी की आधिकारिक वेबसाइट या ऐप पर ट्रैक करें। कूरियर लिंक भेजकर फीस नहीं मांगते।",
               "bn": "পার্সেল শুধু কুরিয়ার কোম্পানির অফিসিয়াল ওয়েবসাইট বা অ্যাপে ট্র্যাক করুন। কুরিয়ার লিঙ্ক পাঠিয়ে ফি চায় না।"},
    "bill_challan": {"en": "Pay bills only in your provider's official app or website. Check e-challans at echallan.parivahan.gov.in.",
                     "hi": "बिल सिर्फ अपनी कंपनी की आधिकारिक ऐप या वेबसाइट पर भरें। ई-चालान echallan.parivahan.gov.in पर जाँचें।",
                     "bn": "বিল শুধু আপনার সংস্থার অফিসিয়াল অ্যাপ বা ওয়েবসাইটে দিন। ই-চালান echallan.parivahan.gov.in-এ যাচাই করুন।"},
    "other": {"en": "Look up the organisation's official contact yourself and check with them directly.",
              "hi": "संस्था का आधिकारिक संपर्क खुद ढूंढें और सीधे उनसे पुष्टि करें।",
              "bn": "সংস্থার অফিসিয়াল যোগাযোগ নিজে খুঁজে সরাসরি তাদের সাথে যাচাই করুন।"},
}

URGENT_STEPS = {
    "en": ["Call 1930 now (National Cyber Crime Helpline). The first hours matter most.",
           "Report at cybercrime.gov.in and keep screenshots, transaction IDs and the sender's number.",
           "Call your bank's official helpline to block your card, UPI or account. Change your UPI PIN and passwords."],
    "hi": ["अभी 1930 पर कॉल करें (राष्ट्रीय साइबर अपराध हेल्पलाइन)। शुरुआती घंटे सबसे ज़रूरी हैं।",
           "cybercrime.gov.in पर शिकायत दर्ज करें और स्क्रीनशॉट, ट्रांज़ैक्शन ID और भेजने वाले का नंबर संभालकर रखें।",
           "अपने बैंक की आधिकारिक हेल्पलाइन पर कॉल करके कार्ड, UPI या खाता ब्लॉक कराएं। UPI पिन और पासवर्ड बदलें।"],
    "bn": ["এখনই ১৯৩০-এ ফোন করুন (জাতীয় সাইবার ক্রাইম হেল্পলাইন)। প্রথম কয়েক ঘণ্টাই সবচেয়ে জরুরি।",
           "cybercrime.gov.in-এ অভিযোগ করুন এবং স্ক্রিনশট, ট্রানজ্যাকশন আইডি ও প্রেরকের নম্বর রেখে দিন।",
           "ব্যাংকের অফিসিয়াল হেল্পলাইনে ফোন করে কার্ড, UPI বা অ্যাকাউন্ট ব্লক করান। UPI পিন ও পাসওয়ার্ড বদলান।"],
}

DISCLAIMER = {
    "en": "This is not a guarantee. For help, call 1930.",
    "hi": "यह कोई गारंटी नहीं है। मदद के लिए 1930 पर कॉल करें।",
    "bn": "এটা কোনো গ্যারান্টি নয়। সাহায্যের জন্য ১৯৩০-এ ফোন করুন।",
}

TOO_SHORT = {
    "en": "There isn't enough here to judge. Paste the whole message, or describe the call.",
    "hi": "जाँचने के लिए इतनी जानकारी काफी नहीं है। पूरा संदेश पेस्ट करें या कॉल के बारे में बताएं।",
    "bn": "যাচাই করার মতো যথেষ্ট তথ্য নেই। পুরো বার্তাটি পেস্ট করুন বা কলের কথা লিখুন।",
}

# Why each rule flag matters (shown as a red flag on the card)
FLAG_WHY = {
    "injection": {"en": "Contains hidden instructions aimed at AI checkers. Real organisations never do this.",
                  "hi": "इसमें AI जाँचने वाले टूल के लिए छिपे निर्देश हैं। असली संस्थाएं ऐसा कभी नहीं करतीं।",
                  "bn": "এতে AI যাচাইকারীর জন্য লুকোনো নির্দেশ আছে। আসল সংস্থা কখনও এমন করে না।"},
    "asks_secret": {"en": "Asks you to share an OTP, PIN, CVV or password. Banks and real companies never ask for these.",
                    "hi": "OTP, पिन, CVV या पासवर्ड बताने को कहा गया है। बैंक और असली कंपनियां ये कभी नहीं मांगतीं।",
                    "bn": "OTP, পিন, CVV বা পাসওয়ার্ড জানাতে বলা হয়েছে। ব্যাংক বা আসল কোম্পানি এগুলো কখনও চায় না।"},
    "pin_to_receive": {"en": "Asks you to enter a PIN or approve a request to receive money. You never need a PIN to receive money; this sends money out.",
                       "hi": "पैसे पाने के लिए पिन डालने या रिक्वेस्ट मंज़ूर करने को कहा गया है। पैसे पाने के लिए पिन कभी नहीं लगता, इससे पैसा आपके खाते से जाता है।",
                       "bn": "টাকা পাওয়ার জন্য পিন দিতে বা রিকোয়েস্ট অনুমোদন করতে বলা হয়েছে। টাকা পেতে কখনও পিন লাগে না, এতে আপনার অ্যাকাউন্ট থেকে টাকা চলে যায়।"},
    "remote_access": {"en": "Asks you to install an app or share your screen. That can let a stranger control your phone.",
                      "hi": "कोई ऐप इंस्टॉल करने या स्क्रीन शेयर करने को कहा गया है। इससे कोई अजनबी आपका फोन चला सकता है।",
                      "bn": "কোনো অ্যাপ ইনস্টল করতে বা স্ক্রিন শেয়ার করতে বলা হয়েছে। এতে অচেনা কেউ আপনার ফোন নিয়ন্ত্রণ করতে পারে।"},
    "apk_file": {"en": "Sends an app file (.apk) to install outside the Play Store. These apps often steal OTPs and bank details.",
                 "hi": "Play Store के बाहर से ऐप (.apk फ़ाइल) इंस्टॉल करने को कहा गया है। ऐसी ऐप अक्सर OTP और बैंक जानकारी चुराती हैं।",
                 "bn": "Play Store-এর বাইরে থেকে অ্যাপ (.apk ফাইল) ইনস্টল করতে বলা হয়েছে। এমন অ্যাপ প্রায়ই OTP ও ব্যাংকের তথ্য চুরি করে।"},
    "digital_arrest": {"en": "Threatens arrest by police or officials and keeps you on a call. There is no such thing as a 'digital arrest'.",
                       "hi": "पुलिस या अधिकारी बनकर गिरफ्तारी की धमकी और कॉल पर रोके रखना। 'डिजिटल अरेस्ट' जैसी कोई चीज़ नहीं होती।",
                       "bn": "পুলিশ বা অফিসার সেজে গ্রেফতারের ভয় দেখানো এবং কলে আটকে রাখা। 'ডিজিটাল অ্যারেস্ট' বলে কিছু হয় না।"},
    "safe_account": {"en": "Asks you to move money to a 'safe', 'RBI' or 'verification' account. No agency ever asks for this.",
                     "hi": "पैसे किसी 'सुरक्षित', 'RBI' या 'वेरिफिकेशन' खाते में भेजने को कहा गया है। कोई भी सरकारी संस्था ऐसा नहीं कहती।",
                     "bn": "টাকা কোনো 'নিরাপদ', 'RBI' বা 'ভেরিফিকেশন' অ্যাকাউন্টে সরাতে বলা হয়েছে। কোনো সরকারি সংস্থা এমন বলে না।"},
    "official_fee_personal_upi": {"en": "Asks you to pay an official fine or fee to a personal UPI ID. Government payments never go to personal IDs.",
                                  "hi": "सरकारी जुर्माना या फीस किसी निजी UPI ID पर भरने को कहा गया है। सरकारी भुगतान कभी निजी ID पर नहीं होते।",
                                  "bn": "সরকারি জরিমানা বা ফি কোনো ব্যক্তিগত UPI ID-তে দিতে বলা হয়েছে। সরকারি পেমেন্ট কখনও ব্যক্তিগত ID-তে যায় না।"},
    "guaranteed_returns": {"en": "Promises guaranteed or very high returns in a short time. Real investments never guarantee profits.",
                           "hi": "कम समय में पक्का या बहुत ज़्यादा मुनाफा देने का वादा। असली निवेश में मुनाफे की गारंटी नहीं होती।",
                           "bn": "অল্প সময়ে নিশ্চিত বা খুব বেশি লাভের প্রতিশ্রুতি। আসল বিনিয়োগে লাভের গ্যারান্টি থাকে না।"},
    "task_scam": {"en": "Pays you to like, rate or review things, or asks you to pay to unlock earnings. This is a known task scam.",
                  "hi": "लाइक, रेटिंग या रिव्यू करने पर पैसे देने का लालच, या कमाई निकालने के लिए पैसे जमा कराना। यह जाना-माना टास्क स्कैम है।",
                  "bn": "লাইক, রেটিং বা রিভিউ করলে টাকা দেওয়ার লোভ, বা আয় তুলতে টাকা জমা করানো। এটা পরিচিত টাস্ক স্ক্যাম।"},
    "power_cut_threat": {"en": "Threatens to cut your electricity tonight and asks you to call an 'officer'. Power companies don't do this.",
                         "hi": "आज रात बिजली काटने की धमकी देकर किसी 'अधिकारी' को कॉल करने को कहता है। बिजली कंपनियां ऐसा नहीं करतीं।",
                         "bn": "আজ রাতে বিদ্যুৎ কেটে দেওয়ার হুমকি দিয়ে কোনো 'অফিসারকে' ফোন করতে বলে। বিদ্যুৎ সংস্থা এমন করে না।"},
    "secrecy": {"en": "Tells you to keep it secret from family or others.",
                "hi": "परिवार या दूसरों से बात छिपाने को कहता है।",
                "bn": "পরিবার বা অন্যদের কাছে গোপন রাখতে বলে।"},
    "new_number_money": {"en": "Someone on a 'new number' is asking for money.",
                         "hi": "'नए नंबर' से कोई पैसे मांग रहा है।",
                         "bn": "'নতুন নম্বর' থেকে কেউ টাকা চাইছে।"},
    "upfront_fee": {"en": "Asks for a fee before you get a job, loan, prize, parcel or refund.",
                    "hi": "नौकरी, लोन, इनाम, पार्सल या रिफंड से पहले फीस मांगता है।",
                    "bn": "চাকরি, লোন, পুরস্কার, পার্সেল বা রিফান্ডের আগে ফি চায়।"},
    "personal_upi_payment": {"en": "Asks you to pay a personal UPI ID instead of an official one.",
                             "hi": "किसी आधिकारिक ID की जगह निजी UPI ID पर पैसे भेजने को कहता है।",
                             "bn": "অফিসিয়াল ID-র বদলে ব্যক্তিগত UPI ID-তে টাকা পাঠাতে বলে।"},
    "prize_lottery": {"en": "Says you've won a prize or lottery you never entered.",
                      "hi": "ऐसे इनाम या लॉटरी जीतने की बात, जिसमें आपने भाग ही नहीं लिया।",
                      "bn": "এমন পুরস্কার বা লটারি জেতার কথা, যাতে আপনি অংশই নেননি।"},
    "lookalike_domain": {"en": "The link looks like a well-known brand's site but isn't its official address.",
                         "hi": "लिंक किसी जानी-मानी कंपनी जैसा दिखता है, पर उसका आधिकारिक पता नहीं है।",
                         "bn": "লিঙ্কটি কোনো পরিচিত কোম্পানির মতো দেখতে, কিন্তু তাদের অফিসিয়াল ঠিকানা নয়।"},
    "risky_link": {"en": "The link uses a short or unusual web address that hides where it goes.",
                   "hi": "लिंक छोटा या अजीब वेब पता है, जिससे पता नहीं चलता कि वह कहाँ ले जाएगा।",
                   "bn": "লিঙ্কটি ছোট বা অদ্ভুত ঠিকানা, যাতে বোঝা যায় না সেটা কোথায় নিয়ে যাবে।"},
    "lure_link": {"en": "The link's address uses words like 'kyc', 'refund' or 'verify' on a site that isn't official.",
                  "hi": "लिंक के पते में 'kyc', 'refund' या 'verify' जैसे शब्द हैं, पर वेबसाइट आधिकारिक नहीं है।",
                  "bn": "লিঙ্কের ঠিকানায় 'kyc', 'refund' বা 'verify'-এর মতো শব্দ, কিন্তু সাইটটি অফিসিয়াল নয়।"},
    "daily_earnings": {"en": "Promises fixed earnings every day.",
                       "hi": "हर दिन तय कमाई का वादा करता है।",
                       "bn": "প্রতিদিন নির্দিষ্ট আয়ের প্রতিশ্রুতি দেয়।"},
    "family_pressure": {"en": "A 'family member' is pressuring you for money with fear or secrecy.",
                        "hi": "'परिवार का सदस्य' डर या राज़दारी के साथ पैसे के लिए दबाव डाल रहा है।",
                        "bn": "'পরিবারের কেউ' ভয় বা গোপনীয়তার সাথে টাকার জন্য চাপ দিচ্ছে।"},
    "official_asks_money": {"en": "Someone claiming to be an official or a company asked you to transfer money on a call.",
                            "hi": "अधिकारी या कंपनी बनकर किसी ने कॉल पर पैसे ट्रांसफर करने को कहा।",
                            "bn": "অফিসার বা কোম্পানি সেজে কেউ ফোনে টাকা পাঠাতে বলেছে।"},
    "return_request": {"en": "A stranger asks you to return money 'sent by mistake'. Check your own bank first: this is a common trick.",
                       "hi": "कोई अजनबी 'गलती से भेजे' पैसे लौटाने को कह रहा है। पहले अपना बैंक खुद जाँचें: यह आम चाल है।",
                       "bn": "অচেনা কেউ 'ভুল করে পাঠানো' টাকা ফেরত চাইছে। আগে নিজের ব্যাংক দেখুন: এটা পরিচিত কৌশল।"},
    "screenshot_claim": {"en": "Uses a screenshot as proof of payment. A screenshot can be faked; only your own bank or UPI app is proof.",
                         "hi": "पेमेंट के सबूत के तौर पर स्क्रीनशॉट दिखाता है। स्क्रीनशॉट नकली हो सकता है; सबूत सिर्फ आपका अपना बैंक या UPI ऐप है।",
                         "bn": "পেমেন্টের প্রমাণ হিসেবে স্ক্রিনশট দেখায়। স্ক্রিনশট নকল হতে পারে; প্রমাণ শুধু আপনার নিজের ব্যাংক বা UPI অ্যাপ।"},
    "withdrawal_fee": {"en": "Asks you to pay a tax or fee before you can withdraw your money. Real platforms deduct charges; they don't ask for deposits.",
                       "hi": "पैसे निकालने से पहले टैक्स या फीस भरने को कहता है। असली प्लेटफॉर्म चार्ज काट लेते हैं, जमा नहीं करवाते।",
                       "bn": "টাকা তোলার আগে ট্যাক্স বা ফি দিতে বলে। আসল প্ল্যাটফর্ম চার্জ কেটে নেয়, জমা করায় না।"},
    "urgency": {"en": "Pushes you to act immediately.", "hi": "तुरंत कुछ करने का दबाव डालता है।", "bn": "এখনই কিছু করার চাপ দেয়।"},
    "threat_block": {"en": "Threatens to block or cut off your account or service.", "hi": "खाता या सेवा बंद करने की धमकी देता है।", "bn": "অ্যাকাউন্ট বা পরিষেবা বন্ধ করার হুমকি দেয়।"},
}

SCREENSHOT_NOTE = {
    "en": "This looks like a payment screen. A screenshot can never prove a payment: check your own UPI app, bank SMS or soundbox.",
    "hi": "यह पेमेंट स्क्रीन जैसा दिखता है। स्क्रीनशॉट से पेमेंट कभी साबित नहीं होता: अपना UPI ऐप, बैंक SMS या साउंडबॉक्स जाँचें।",
    "bn": "এটা পেমেন্টের স্ক্রিনের মতো দেখাচ্ছে। স্ক্রিনশট দিয়ে পেমেন্ট কখনও প্রমাণ হয় না: নিজের UPI অ্যাপ, ব্যাংক SMS বা সাউন্ডবক্স দেখুন।",
}

_SHARE = {
    "en": ("I checked a suspicious message on Is This a Scam?", "Verdict", "Never share an OTP or UPI PIN. For help, call 1930."),
    "hi": ("मैंने 'Is This a Scam?' पर एक संदिग्ध संदेश जाँचा।", "नतीजा", "OTP या UPI पिन कभी किसी को न बताएं। मदद के लिए 1930 पर कॉल करें।"),
    "bn": ("আমি 'Is This a Scam?'-এ একটি সন্দেহজনক বার্তা যাচাই করেছি।", "ফলাফল", "OTP বা UPI পিন কখনও কাউকে বলবেন না। সাহায্যের জন্য ১৯৩০-এ ফোন করুন।"),
}


def next_steps(verdict: str, lang: str) -> list[str]:
    return NEXT_STEPS[verdict][lang]


def verify_tip(scam_type: str | None, lang: str) -> str:
    return VERIFY.get(scam_type or "other", VERIFY["other"])[lang]


def flag_why(code: str, lang: str) -> str | None:
    return FLAG_WHY.get(code, {}).get(lang)


def share_text(verdict: str, scam_type: str | None, lang: str) -> str:
    """Verdict and type only: the original message is never included."""
    intro, label, tail = _SHARE[lang]
    line = f"{label}: {VERDICT_LABELS[verdict][lang]}"
    if verdict == "scam" and scam_type:
        line += f" ({TYPE_LABELS[scam_type][lang]})"
    return f"{intro}\n{line}\n{tail}"
