"""Scam rules in English, Hinglish, Hindi, Telugu and Tenglish.

Three kinds of rule:
  red     - scam evidence (each has a weight 0..1; "critical" ones alone mean SCAM)
  verify  - "Things to verify": not proof, but check before acting
  good    - "Good signs": genuine messages point to official channels and warn against sharing secrets

Rules match on the NORMALISED text (see normalize.py). Weights live here next to each rule.
Rules never contain benchmark messages - they describe general scam patterns.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

S = r"[^.!?\n।]"  # "same sentence" character
# Negation words that turn a request into a warning ("do NOT share your OTP").
NEG_BEFORE = re.compile(
    r"\b(do not|don't|dont|never|not to|no one|nobody|mat|kabhi|kabhi bhi)\b|न |ना |मत |नहीं|कभी|ఎప్పుడూ")
NEG_AFTER = re.compile(
    r"^\W{0,3}(\S+\s){0,1}\S*(vaddu|cheyakandi|cheppakandi|ivvakandi|mat|na karein|na karo|nahi|వద్దు|కండి|కూడదు)")


@dataclass
class Rule:
    id: str
    kind: str                 # red | verify | good
    name: str
    weight: float
    patterns: list[str]
    why: str
    tags: frozenset = field(default_factory=frozenset)
    critical: bool = False
    negatable: bool = False   # skip the match when a negation is next to it
    exclude: str | None = None  # skip when this appears anywhere in the message
    compiled: list = field(default_factory=list, repr=False)

    def __post_init__(self):
        self.compiled = [re.compile(p.replace("{S}", S)) for p in self.patterns]
        self.exclude_re = re.compile(self.exclude.replace("{S}", S)) if self.exclude else None


def _r(id, kind, name, weight, patterns, why, tags=(), **kw):
    return Rule(id, kind, name, weight, patterns, why, frozenset(tags), **kw)


RULES: list[Rule] = [
    # ======================= RED FLAGS =======================
    _r("otp_request", "red", "Asks for OTP / PIN / CVV / password", 0.9, [
        r"\b(share|send|forward|tell|give|provide|enter|type|read out|say|confirm|reply with|whatsapp)\b{S}{0,40}"
        r"\b(otp|one time password|verification code|security code|login code|(\d|four|six)[- ]digit (code|number|otp)|"
        r"upi pin|atm pin|mpin|pin|cvv|password|card number|card details|expiry)\b",
        r"\b(otp|verification code|pin|cvv|password)\b{S}{0,30}\b(share|send|forward|tell|batao|bataiye|bataye|bata do|"
        r"bhejo|bhej do|bhejiye|dijiye|de do|share karo|share karein|cheppandi|cheppu|pampandi|pampu|ivvandi|"
        r"share cheyandi|send cheyandi|enter cheyandi)\b",
        r"(otp|ओटीपी|पिन|पासवर्ड){S}{0,25}(भेज|बता|दर्ज|शेयर कर|दें|दीजिए|दे दो)",
        r"(otp|ఓటీపీ|పిన్|పాస్‌వర్డ్|పాస్వర్డ్){S}{0,30}(చెప్ప|పంప|నమోదు|ఇవ్వ|షేర్|పంచుకో)",
    ], "Real banks and apps NEVER ask you to share, forward or enter your OTP, UPI PIN, CVV or password.",
        ["credential"], critical=True, negatable=True),

    _r("pin_to_receive", "red", "Enter PIN / approve request to RECEIVE money", 0.9, [
        r"\b(enter|type|scan|put|daalo|dalo)\b{S}{0,40}\b(pin|qr)\b{S}{0,40}\b(receive|get|credit|lene|paane|milega)\b",
        r"\b(receive|get|accept|claim)\b{S}{0,40}\b(enter|scan|approve)\b{S}{0,30}\b(pin|qr|request)\b",
        r"\bto (receive|get) (the |your )?(money|payment|amount|refund|cashback)\b{S}{0,40}\b(approve|accept|scan|pin)\b",
        r"\b(approve|accept)\b{S}{0,40}\bto (receive|get)\b",
        r"\b(paise|payment|paisa)\b{S}{0,30}\b(lene|pane|paane|receive)\b{S}{0,30}\b(pin|qr|scan|approve)\b",
        r"(पैसे|रकम|पेमेंट){S}{0,30}(पाने|लेने|प्राप्त){S}{0,30}(पिन|pin|qr|स्कैन)",
        r"(డబ్బు|పేమెంట్){S}{0,30}(పొంద|స్వీకరించ){S}{0,30}(పిన్|pin|qr|స్కాన్)",
    ], "You never need to enter a UPI PIN, scan a QR code or approve a request to RECEIVE money - only to send it.",
        ["upi", "credential"], critical=True, negatable=True),

    _r("remote_app", "red", "Asks you to install a remote-access app", 0.85, [
        r"\b(anydesk|any desk|teamviewer|team viewer|quicksupport|quick support|airdroid|rustdesk|ultraviewer)\b",
        r"\bscreen ?shar(e|ing) (app|application)\b",
    ], "Screen-sharing apps let scammers control your phone and empty your account.", ["remote"], critical=True),

    _r("apk", "red", "Asks you to install an app from a link", 0.7, [
        r"\.apk\b", r"\bdownload\b{S}{0,30}\bapk\b",
        r"\binstall\b{S}{0,30}\b(app|application)\b{S}{0,20}\b(from|via|using) (this )?(link|whatsapp)\b",
    ], "Apps from links (APK files) can steal OTPs and banking data. Install apps only from the Play Store.",
        ["malware"]),

    _r("link", "red", "Contains a link", 0.25, [
        r"(https?://|hxxps?://|www\.)\S+",
        r"(?<![@\w.-])[a-z0-9-]+(\.[a-z0-9-]+)*\.(in|com|net|co|app|xyz|info|link|top|site|online|club|live|org|test)\b(/\S*)?",
    ], "Scam links often copy real names. Open only the official app or type the website yourself.", ["link"]),

    _r("shortener", "red", "Uses a short link that hides the real website", 0.35, [
        r"\b(bit\.ly|tinyurl\.com|t\.co|cutt\.ly|rb\.gy|is\.gd|shorturl\.at|tiny\.cc|ow\.ly|goo\.gl|s\.id|t\.ly)/",
    ], "Short links hide where they really go. Genuine banks rarely use them.", ["link", "shortener"]),

    _r("lookalike_domain", "red", "Lookalike / fake website address", 0.5, [
        r"\b[a-z0-9-]*(sbi|hdfc|icici|axis|kotak|paytm|phonepe|gpay|googlepay|amazon|flipkart|airtel|jio|fedex|dhl|"
        r"bluedart|indiapost|irctc|uidai|aadhaar|epfo|incometax|npci|rbi|fastag|bescom|tneb|bses|electricity|netflix|"
        r"whatsapp|instagram|google|bank|delivery|courier|refund|tax|mail)[a-z0-9-]*[-.](kyc|verify|verification|update|"
        r"secure|security|refund|reward|rewards|help|support|login|claim|bonus|gift|pay|billing|redeliver|redelivery|"
        r"track|tracking|service|care|quota|check)[a-z0-9.-]*\.[a-z]{2,}",
        r"\b(kyc|verify|update|secure|refund|reward|claim|login)[a-z0-9-]*[-.](sbi|hdfc|icici|axis|paytm|phonepe|"
        r"amazon|flipkart|airtel|jio|fedex|epfo|bank|help)[a-z0-9.-]*\.[a-z]{2,}",
    ], "The website name mixes a brand or service with words like 'kyc', 'verify' or 'refund' - a classic fake site.",
        ["link", "impersonation"]),

    _r("urgency", "red", "Urgency / time pressure", 0.25, [
        r"\b(urgent|urgently|immediately|right now|asap|at once|within \d+ (hours?|hrs?|minutes?|mins?)|"
        r"in \d+ (hours?|hrs?|minutes?|mins?)|last (date|chance|warning|reminder)|final (notice|warning|reminder)|"
        r"expires? today|expiring today|today itself|tonight|limited (slots|time|period|offer)|only today|hurry|act now)\b",
        r"\b(turant|abhi ke abhi|jaldi karo|jaldi|ghante mein|aaj raat|aaj hi|band ho jayega|band ho jaayega|"
        r"band kar diya jayega|block ho jayega)\b",
        r"(तुरंत|तुरन्त|आज रात|आज ही|घंटे में|बंद हो जाएगा|बंद कर दिया जाएगा|ब्लॉक हो जाएगा)",
        r"(వెంటనే|ఈ రోజే|ఈరోజే|గంటల్లో|గంటలలో|బ్లాక్ అవుతుంది|నిలిపివేయబడుతుంది|నిలిపివేస్తాం|రద్దు అవుతుంది)",
        r"\b(ventane|ippude|gantallo|block avutundi|block avtundi|cancel avutundi|aagipotundi)\b",
    ], "Creates panic so you act without thinking. Real organisations give proper notice.", ["urgency"]),

    _r("account_threat", "red", "Account / KYC / SIM block threat", 0.4, [
        r"\b(kyc|ekyc)\b{S}{0,40}\b(pending|expire|expired|expiring|update|incomplete|not (updated|completed|verified)|"
        r"suspend|block|blocked|required|mandatory|verify)\b",
        r"\b(account|card|wallet|sim|number|connection|upi|net ?banking|mailbox|email|fastag|subscription)\b{S}{0,30}"
        r"\b(will be|has been|is|are|got|being|may be)\b{S}{0,15}\b(blocked|suspended|frozen|restricted|closed|"
        r"deactivated|disabled|terminated|deleted|locked|on hold|barred|limited)\b",
        r"\b(pan|aadhaar)\b{S}{0,30}\b(not linked|link now|update|suspend|blocked|expired?)\b",
        r"\b(account|khata|sim|card)\b{S}{0,30}\b(band|block|suspend)\b{S}{0,15}\b(ho jayega|ho jaayega|kar diya jayega|hoga|ho gaya)\b",
        r"(खाता|अकाउंट|सिम|कार्ड){S}{0,30}(बंद|ब्लॉक|निलंबित)",
        r"(ఖాతా|అకౌంట్|సిమ్|కార్డ్){S}{0,30}(బ్లాక్|నిలిపి|రద్దు|సస్పెండ్)",
        r"\b(account|khata|sim|card)\b{S}{0,30}\b(block|suspend|cancel)\b{S}{0,10}\b(avutundi|avtundi|chestam|chestham)\b",
    ], "Fake KYC / account-block messages are the most common bank scam in India. Check in the official app or branch.",
        ["account_threat"]),

    _r("authority_threat", "red", "Police / legal threat", 0.45, [
        r"\b(police|cyber ?cell|cyber crime (department|branch|cell)|cbi|ncb|narcotics|enforcement directorate|"
        r"crime branch|customs (department|officer)|court|warrant|fir|arrest|arrested|digital arrest|legal action|"
        r"case (is |has been )?(registered|filed)|money laundering|drugs found|illegal (items|parcel|activity|activities))\b",
        r"\b(giraftar|giraftari|police case|jail|arrest ho)\b",
        r"(पुलिस|गिरफ्तार|सीबीआई|कोर्ट|वारंट|केस दर्ज|डिजिटल अरेस्ट|अवैध)",
        r"(పోలీస్|పోలీసు|అరెస్ట్|అరెస్టు|కోర్టు|వారెంట్|కేసు నమోదు|సీబీఐ|అక్రమ)",
    ], "Police, CBI and courts never demand money by message or call. 'Digital arrest' is always a scam.",
        ["authority"]),

    _r("fee_first", "red", "Asks for a fee before giving you something", 0.5, [
        r"\b(registration|processing|verification|delivery|redelivery|re-delivery|security|gst|customs|membership|"
        r"training|visa|shipping|activation|release|unlock|joining|handling|clearance|file|kit|documentation|"
        r"courier|refundable)\s+(fee|fees|charge|charges|amount|deposit|duty|money)\b",
        r"\b(pay|deposit|transfer|send)\b{S}{0,30}\b(fee|fees|charges?|deposit)\b{S}{0,40}\b(to (get|receive|claim|"
        r"release|activate|start|confirm|reserve|unlock)|for (the )?(offer letter|job|prize|loan|refund|parcel|delivery|release))\b",
        r"\b(offer letter|joining|job|prize|loan|refund|reward|subsidy|parcel)\b{S}{0,40}\b(after|on|upon) (payment|paying)\b",
        r"\b(fees?|charge|shulk)\b{S}{0,20}\b(bharo|bhariye|jama karo|jama karein|dena hoga|dena padega|pay karo)\b",
        r"(शुल्क|फीस|चार्ज){S}{0,30}(जमा|भरें|भुगतान|दें|देना होगा)",
        r"(ఫీజు|రుసుము|చార్జ్|ఛార్జ్){S}{0,30}(చెల్లించ|కట్ట|పంప)",
        r"\b(fee|fees|charge)\b{S}{0,20}\b(kattandi|katte|pay cheyandi|pampandi)\b",
    ], "Genuine jobs, prizes, refunds and deliveries never ask you to pay first.", ["fee", "payment"]),

    _r("pay_demand", "red", "Asks you to send money", 0.3, [
        r"\b(pay|send|transfer|deposit|remit)\b{S}{0,25}\brs \d+",
        r"\b(rs \d+|paise|paisa|amount)\b{S}{0,25}\b(bhejo|bhej do|bhejiye|transfer karo|transfer kar do|jama karo|daalo|dalo)\b",
        r"(rs \d+|पैसे|रुपये){S}{0,30}(भेजें|भेजो|ट्रांसफर|जमा करें|डालें)",
        r"(rs \d+|డబ్బు|రూపాయలు){S}{0,30}(పంపండి|పంపు|చెల్లించండి|బదిలీ|ట్రాన్స్‌ఫర్|కట్టండి)",
        r"\b(rs \d+|dabbulu|dabbu|money)\b{S}{0,25}\b(pampandi|pampu|transfer cheyandi|kattandi|send cheyandi)\b",
    ], "Asks you to send money. Verify the person and reason through a known, official contact first.", ["payment"]),

    _r("prize", "red", "Prize / lottery you never entered", 0.45, [
        r"\b(you('ve| have)? won|you are (the )?(lucky )?winner|winner of|lottery|lucky draw|jackpot|prize money|"
        r"claim (your )?(prize|reward|gift)|selected for (a |an )?(gift|prize|reward))\b",
        r"\bcongratulations\b{S}{0,40}\b(won|winner|prize|reward|gift)\b",
        r"\b(jeeta|jeete|jeet gaye|inaam|lottery lagi)\b",
        r"(लॉटरी|इनाम|जीत लिया|जीते हैं|लकी ड्रॉ)",
        r"(లాటరీ|బహుమతి|గెలుచుకున్నారు|గెలిచారు|లక్కీ డ్రా)",
        r"\b(gelucharu|gelicharu|bahumati)\b",
    ], "Unexpected prizes are bait. If you never entered, you did not win.", ["prize"]),

    _r("guaranteed_returns", "red", "Guaranteed / unrealistic investment returns", 0.6, [
        r"\bguarantee(d)?\b{S}{0,30}\b(return|returns|profit|profits|income|earning|earnings|payout)\b",
        r"\b(return|returns|profit|profits|income|earning)\b{S}{0,20}\bguarantee(d)?\b",
        r"\bdouble (your )?(money|investment|amount)\b",
        r"\b\d+ ?% (daily|weekly|monthly|per day|per week|per month|every day|every week)\b",
        r"\b(100|200|300|500) ?% (profit|return|returns)\b",
        r"\b(risk[- ]free|no risk|zero risk)\b{S}{0,30}\b(profit|return|returns|investment|income)\b",
        r"\binvest\b{S}{0,30}\brs \d+\b{S}{0,40}\b(get|receive|earn)\b{S}{0,20}\brs \d+",
        r"\b(paisa double|paise double|double paisa|guaranteed munafa|pakka profit|munafa pakka)\b",
        r"(पैसा डबल|पैसे डबल|गारंटी(ड)? (रिटर्न|मुनाफा|लाभ)|मुनाफा पक्का|दोगुना)",
        r"(రెట్టింపు|గ్యారంటీ(డ్)? (లాభం|రిటర్న్)|లాభం ఖచ్చితం)",
        r"\b(double avutundi|rettimpu|guaranteed labham)\b",
    ], "No real investment can guarantee high returns. 'Guaranteed profit' is the #1 sign of investment fraud.",
        ["investment"]),

    _r("investment_pitch", "red", "Trading / tips group pitch", 0.3, [
        r"\b(trading (group|signals?|tips?)|stock tips?|vip (group|tips|signals)|crypto (signals?|group|trading)|"
        r"forex|binary options?|ipo allotment (group|tips)|telegram (group|channel))\b",
    ], "Unknown 'VIP trading groups' are a common way to pull people into investment scams.", ["investment"]),

    _r("easy_money_job", "red", "Easy online work for big money", 0.45, [
        r"\b(part[- ]?time (job|work)|work from home|home based (job|work)|daily (salary|payment|income|payout)|"
        r"earn rs \d+|per (task|review|like)|like (youtube )?(videos|posts)|(rate|rating|review) (hotels|products|"
        r"restaurants|movies)|prepaid task|simple (task|tasks|work)|data entry (job|work)|telegram (task|job)|"
        r"typing (job|work)|earn (money|extra|daily))\b",
        r"\b(ghar baithe|roz kamao|kamai karo|kamaiye|daily kamai)\b",
        r"(घर बैठे|रोज़? कमाएं|कमाई करें|दैनिक कमाई)",
        r"(ఇంటి నుండి|ఇంట్లో నుండి|రోజుకు rs|రోజుకి rs|సులభమైన పని|పార్ట్ టైమ్)",
        r"\b(intlo nundi|roju ki rs|rojuki rs|part time pani)\b",
    ], "'Like videos / rate hotels and earn daily' jobs are task scams that end with you paying them.",
        ["job_offer"]),

    _r("no_interview", "red", "Job with no interview", 0.4, [
        r"\b(no interview|without (any )?interview|interview not required|no (technical )?(interview|test) "
        r"(required|needed)|direct (joining|selection|appointment)|selected without)\b",
        r"\bbina interview\b", r"(बिना इंटरव्यू|बिना साक्षात्कार)", r"(ఇంటర్వ్యూ లేకుండా)", r"\binterview lekunda\b",
    ], "Real employers interview candidates. 'No interview needed' plus a big salary is a fake-job sign.",
        ["job_offer"]),

    _r("unknown_number", "red", "Asks you to contact a personal mobile number", 0.25, [
        r"\b(call|whatsapp|contact|message|sms|reach|dial|phone)\b{S}{0,35}\b[6-9]\d{9}\b",
        r"wa\.me/",
        r"\b[6-9]\d{9}\b{S}{0,20}\b(par|pe|ki|ku) (call|whatsapp|contact)\b",
        r"[6-9]\d{9}{S}{0,15}(पर कॉल|पर संपर्क|కి కాల్|కు కాల్)",
    ], "Use only phone numbers from the official website or the back of your card.", ["contact"]),

    _r("secrecy", "red", "Asks you to keep it secret", 0.45, [
        r"\b(don't|do not|dont|never) (tell|inform|share (this|it) with|discuss (this|it) with) (anyone|anybody|"
        r"your family|family|bank|police|others)\b",
        r"\bkeep (this|it) (secret|confidential|between us)\b", r"\bconfidential (matter|investigation)\b",
        r"\b(kisi ko mat batana|kisi ko na batayein|ghar walon ko mat)\b",
        r"(किसी को|परिवार को) (मत|न) (बताना|बताएं|बताएँ)",
        r"(ఎవరికీ చెప్పవద్దు|ఎవరితో చెప్పకండి)", r"\b(evvariki cheppakandi|evariki cheppaku)\b",
    ], "Scammers isolate victims so nobody can warn them.", ["secrecy"],
        # "Don't tell anyone" about an OTP/code is a genuine safety warning, not secrecy.
        exclude=r"(otp|\bpin\b|password|cvv|\bcode\b|ओटीपी|पिन|కోడ్|పిన్|ఓటీపీ)"),

    _r("money_mule", "red", "Money-mule recruitment", 0.65, [
        r"\b(receive|accept|collect)\b{S}{0,40}\b(money|payments?|funds|amount|transfers?)\b{S}{0,40}\b(forward|transfer|send|withdraw)\b",
        r"\bkeep \d+ ?%", r"\b\d+ ?% commission\b",
        r"\b(rent|lend|sell|give) (your |us your )?(bank )?(account|accounts|upi id|sim)\b",
        r"\baccount (on|for) rent\b", r"\bcurrent account (holders?|required)\b",
        r"\b(account kiraye|khata kiraye|commission milega|aage bhej)\b",
        r"(खाते में पैसे{S}{0,40}(आगे|ट्रांसफर)|किराये पर खाता)",
        r"(ఖాతాలో డబ్బు{S}{0,40}(పంపండి|బదిలీ))", r"\b(commission istam|commission vastundi|account rent)\b",
    ], "Moving other people's money through your account is money laundering - you can be arrested for it.",
        ["mule"]),

    _r("emotional", "red", "Emergency / emotional pressure", 0.2, [
        r"\b(accident|hospital|icu|emergency|in trouble|stuck (at|in)|stranded|kidnapped|"
        r"lost (my|his|her|their) (phone|wallet|passport)|phone (broke|is broken|got broken)|"
        r"i will explain later|explain later|can'?t talk|cannot talk)\b",
        r"\b(musibat|hospital mein|accident ho gaya|phas gaya|phas gayi|baad mein bataunga|baad mein batata)\b",
        r"(मुसीबत|अस्पताल|एक्सीडेंट|दुर्घटना|फंस गया|फंस गई|बाद में बताऊंगा)",
        r"(ఆసుపత్రి|ప్రమాదం|ఇబ్బందిలో|చిక్కుకున్నాను|తర్వాత చెప్తాను)",
        r"\b(hospital lo|accident ayindi|ibbandi lo|taruvata chepta|tarvata cheptha)\b",
        r"\b(my love|darling|sweetheart|honey|baby)\b{S}{0,60}\b(gift|parcel|customs|send|money|transfer|help me)\b",
    ], "Emergencies from unknown numbers are used to rush you. Call the person on their old number first.",
        ["emotional"]),

    _r("sextortion", "red", "Threat to leak photos / videos", 0.6, [
        r"\b(video|videos|photo|photos|pictures?|recording)\b{S}{0,40}\b(viral|leak|share with (your )?(family|contacts|friends)|upload|send to (your )?(family|contacts))\b",
    ], "Blackmail threats are a crime. Don't pay - report at cybercrime.gov.in or call 1930.", ["threat", "authority"]),

    _r("sensitive_data", "red", "Asks for bank or identity details", 0.55, [
        r"\b(send|share|confirm|update|enter|provide|submit|verify)\b{S}{0,40}\b(card number|debit card|credit card "
        r"details|expiry( date)?|cvv|bank details|account number|ifsc|net ?banking (id|password|credentials)|"
        r"login (id|details|credentials)|password|aadhaar number|pan( number| details)?|passport( copy| scan| number)?)\b",
        r"(आधार नंबर|पैन|कार्ड नंबर|पासवर्ड|बैंक विवरण){S}{0,30}(भेज|बता|दर्ज|शेयर)",
        r"(ఆధార్ నంబర్|పాన్|కార్డ్ నంబర్|పాస్‌వర్డ్|బ్యాంక్ వివరాలు){S}{0,30}(పంప|చెప్ప|నమోదు|ఇవ్వ)",
    ], "Never send card, bank, Aadhaar, PAN or passport details to someone who messaged you first.",
        ["credential"], negatable=True),

    _r("refund_bait", "red", "Refund / wrong-transfer bait", 0.35, [
        r"\b(reverse the (failed )?transaction|credited (to your account )?by mistake|wrongly (credited|transferred|sent)|"
        r"sent (you )?by mistake|return (it|the money|the amount))\b",
        r"\brefund\b{S}{0,40}\b(claim|click|verify|confirm|enter|approve)\b",
        r"\bcashback\b{S}{0,30}\b(claim|receive|enter|scan|approve)\b",
    ], "'Money sent by mistake' and fake refunds are used to make you send money or approve a request.", ["refund"]),

    _r("delivery_issue", "red", "Parcel problem message", 0.25, [
        r"\b(parcel|package|shipment|courier|consignment)\b{S}{0,50}\b(on hold|held|pending|failed|undelivered|"
        r"returned|could not be delivered|address (is )?(incomplete|wrong|invalid)|redeliver|re-deliver|customs|seized|illegal)\b",
        r"(पार्सल|कूरियर){S}{0,40}(रुका|होल्ड|अवैध|कस्टम)",
        r"(పార్సెల్|కొరియర్){S}{0,40}(ఆపి|హోల్డ్|అక్రమ|కస్టమ్స్)",
    ], "Fake delivery problems lure you to links or small payments. Check in the app you ordered from.", ["delivery"]),

    _r("utility_disconnect", "red", "Electricity / gas disconnection threat", 0.45, [
        r"\b(electricity|power|current|bijli|light|gas)\b{S}{0,50}\b(disconnect|disconnected|disconnection|cut|"
        r"cut off|katega|kat jayega|kaat diya|kaat di jayegi)\b",
        r"(बिजली|गैस){S}{0,40}(कट|काट|बंद)",
        r"(కరెంట్|విద్యుత్|కరెంటు){S}{0,40}(కట్|నిలిపి|ఆపి)",
        r"\bcurrent (cut|katt)\b",
    ], "Electricity boards don't threaten tonight's disconnection by SMS with a personal number to call.",
        ["utility"]),

    _r("gov_impersonation", "red", "Government scheme / tax claim", 0.2, [
        r"\b(government|pradhan mantri|yojana|subsidy|income tax (department|refund)|tax refund|epfo|"
        r"pf (amount|claim|withdrawal)|rbi|trai|uidai|ministry|scheme)\b",
        r"(सरकार|योजना|सब्सिडी|आयकर)", r"(ప్రభుత్వ|పథకం|సబ్సిడీ)",
    ], "Government departments don't ask for fees or bank details by SMS/WhatsApp.", ["gov"]),

    _r("bank_impersonation", "red", "Claims to be from a bank / company", 0.3, [
        r"\b(i am|this is|we are|calling from|message from)\b{S}{0,25}\b(your )?(bank|sbi|hdfc|icici|axis|kotak|rbi|"
        r"paytm|phonepe|google pay|amazon|flipkart|customer care|customer support|head office|bank manager|"
        r"branch manager|bank officer|kyc (team|department)|verification team|security team|fraud (team|department))\b",
        r"\b(main bank se|bank se bol raha)\b", r"(मैं बैंक से|बैंक से बोल)", r"(బ్యాంక్ నుండి మాట్లాడ)",
    ], "Anyone can claim to be from a bank. Call the bank yourself on the official number.", ["impersonation"]),

    _r("loan_app", "red", "Instant loan with no checks", 0.4, [
        r"\b(instant loan|loan (approved|sanctioned) (instantly|in \d+ minutes)|without (any )?documents|"
        r"no (cibil|credit) (check|score))\b",
    ], "Instant 'no-document' loan apps often steal contacts and harass borrowers.", ["loan"]),

    _r("ai_injection", "red", "Tries to give instructions to AI checkers", 0.55, [
        r"(#{2,}\s*system|\[system\]|<\s*/?\s*system\s*>|\bsystem (prompt|message|override|instruction)\b)",
        r"\b(as|you are) (an? )?(ai|assistant|language model|classifier|scam checker|scam detector|scamshield)\b",
        r"\b(classify|label|mark|flag|rate|treat|report)\b{S}{0,25}\bas (safe|legit|legitimate|genuine|not (a )?scam)\b",
        r"\b(label|verdict|classification|output|result)\s*[:=]\s*\"?(safe|legit|genuine)",
        r"\b(developer|admin) (mode|instruction|instructions|override|here)\b",
        r"\bverified (safe|by (rbi|ai|scamshield|google|government|npci))\b",
        r"\bdo not (flag|mark|report) (this|it)\b", r"\"(label|verdict)\"\s*:",
        r"\b(isko|ise) (safe|surakshit) (batao|bataye|maano|mano)\b",
        r"(सुरक्षित|सेफ) (बताएं|बताओ|मानें|बताइए)", r"(సురక్షితం|సేఫ్) అని (చెప్పు|చెప్పండి|గుర్తించ)",
        r"\bsafe ani (cheppu|cheppandi)\b",
    ], "The message tries to instruct AI tools to call it safe. Genuine messages never do this.", ["injection"]),

    _r("ignore_instructions", "red", "Says 'ignore previous instructions'", 0.2, [
        r"\b(ignore|disregard|forget|override)\b{S}{0,30}\b(previous|prior|above|earlier|all|your|system)\b{S}{0,20}"
        r"\b(instructions?|rules?|prompts?|guidelines)\b",
    ], "Phrases like 'ignore previous instructions' are often aimed at AI tools.", ["injection_weak"]),

    # ======================= THINGS TO VERIFY =======================
    _r("new_number", "verify", "Claims to be someone you know on a new number", 0.0, [
        r"\b(changed my number|new number|my new number|using (a |my )?(new|another|friend's|different) (number|phone)|"
        r"this is my new|save (this|my) (new )?(number|contact)|lost (my|his|her|their) phone)\b",
        r"\b(naya number|mera naya number)\b", r"(नया नंबर)", r"(కొత్త నంబర్)", r"\b(kotha number|kottha number)\b",
    ], "Confirm it's really them by calling their old number or meeting before trusting any request.", ["emotional"]),

    _r("approve_request", "verify", "Asks you to approve a payment request", 0.0, [
        r"\b(approve|accept)\b{S}{0,40}\b(payment|request|collect|mandate|autopay)\b",
        r"\b(payment|collect|money) request\b{S}{0,40}\b(pending|received|approve)\b",
        r"(अनुरोध|रिक्वेस्ट){S}{0,30}(स्वीकार|अप्रूव)", r"(రిక్వెస్ట్|అభ్యర్థన){S}{0,30}(ఆమోదించ|approve|అంగీకరించ)",
    ], "Approving a UPI 'collect' request takes money OUT of your account. Decline anything you don't recognise.",
        ["upi"]),

    _r("personal_details", "verify", "Asks for personal details", 0.0, [
        r"\b(share|confirm|send|tell|provide|give)\b{S}{0,40}\b(address|building( name)?|flat number|location|landmark|"
        r"last (four|4) digits|date of birth|dob|full name|email id|selfie)\b",
        r"(पता|लोकेशन){S}{0,20}(भेज|बता|शेयर)", r"(చిరునామా|అడ్రస్|లొకేషన్){S}{0,20}(పంప|చెప్ప|షేర్)",
    ], "Check who is asking (in the official app) before sharing personal details.", []),

    _r("invoice", "verify", "Unexpected invoice / bank-detail change", 0.0, [
        r"\binvoice\b{S}{0,80}\b(payment|pay|process|transfer|due)\b",
        r"\b(process|release|make) (the )?payment\b", r"\b(updated|changed|new) bank (details|account)\b",
    ], "Invoice fraud is common. Confirm with the sender on a number you already know before paying.", ["payment_soft"]),

    _r("unsolicited_offer", "verify", "Unexpected offer or invitation", 0.0, [
        r"\b(free|exclusive|special)\b{S}{0,40}\b(webinar|workshop|course|offer|trial|session|seminar)\b",
        r"\b(rs \d{5,}|\d+ lpa|\d+ lakh)\b{S}{0,25}\b(per month|monthly|salary|package)\b",
        r"\bremote (role|job|position)\b{S}{0,60}\b(salary|paying|pay)\b",
    ], "May be genuine - check the company on its official website, which you open yourself.", []),

    _r("account_warning", "verify", "Account warning / 'verify now'", 0.0, [
        r"\b(final warning|verify now|verify your (identity|account|details)|unusual (activity|login|sign-?in)|"
        r"suspicious (activity|login)|account may be (restricted|limited|suspended)|confirm your (identity|account)|"
        r"re-?activate your account)\b",
    ], "Open the official app directly to check. Don't use buttons or links in the message.", []),

    _r("unverified_caller", "verify", "Unverified person says they are from a company", 0.0, [
        r"\b(i am|this is|i'm)\b{S}{0,25}\bfrom (the )?(delivery|courier|company|hr|recruitment|customer|support|office)\b",
        r"\b(delivery|courier) (boy|agent|executive|partner|team)\b",
    ], "Confirm through the official app or company before sharing anything.", []),

    _r("call_tollfree", "verify", "Asks you to call a number", 0.0, [
        r"\b(call|contact|dial)\b{S}{0,40}\b18\d{8,9}\b",
    ], "Check that the number matches the one on the official website or your card.", []),

    # ======================= GOOD SIGNS =======================
    _r("official_channel", "good", "Points you to the official app / website / branch", 0.6, [
        r"\bofficial (mobile )?(app|application|website|site|portal|helpline|channel)\b",
        r"\b(visit|go to) (a|your|the nearest|nearest|the) (bank )?branch\b",
        r"\bopen (the |your )?(bank |official )?app directly\b", r"\b(the|your) app you (used|use)\b",
        r"\bnumber (printed )?on (the back of )?(your|its) (card|official website|passbook|statement)\b",
        r"\busing your usual bookmark\b", r"\btype the (website|address) yourself\b",
        r"\bin (the|your) (bank'?s? |provider'?s? |official )?app\b",
        r"\b(official app (mein|me|se)|branch (jaayein|jaaiye|jayein|visit karein)|app mein (check|dekhein|dekho))\b",
        r"(आधिकारिक|अधिकारिक|ऑफिशियल)(\s+\S+){0,2}\s*(ऐप|वेबसाइट|पोर्टल)|ऐप में|शाखा (जाएं|में जाएं|पर जाएं)",
        r"(అధికారిక|అఫీషియల్|యాప్‌లో|యాప్ లో|బ్రాంచ్‌కు|బ్రాంచ్ కి)",
        r"\b(official app lo|official website lo|app lo check|branch ki vellandi)\b",
    ], "Genuine messages tell you to use the official app or website yourself.", []),

    _r("dont_share_warning", "good", "Warns you NOT to share OTP / PIN", 0.6, [
        r"\b(do not|don't|dont|never|not to)\b{S}{0,15}\b(share|disclose|tell|give|reveal)\b{S}{0,30}"
        r"\b(otps?|pins?|passwords?|cvv|card details|code)\b",
        r"\b(otps?|pins?|passwords?|cvv)\b{S}{0,30}\b(with|to) (anyone|anybody|no one)\b",
        r"\bnever asks? (for )?(your )?(otp|pin|password|cvv)\b", r"\b(bank|we) (will )?never (ask|call|request)\b",
        r"\b(do not|don't|dont|never) share (it|this|this code|the code)\b{S}{0,20}\b(anyone|anybody)\b",
        r"(इसे|इसको|यह कोड) (किसी को |किसी के साथ )?(न|ना|मत) (बताएं|बताएँ|बताए|शेयर)",
        r"\b(otp|pin)\b{S}{0,25}\b(kisi ko|kisiko)?\s*(share )?(mat|na|nahi) (karein|karo|kare|batayein|batao|bataye|dein|do)\b",
        r"(ओटीपी|otp|पिन|पासवर्ड){S}{0,30}(न|ना|मत|कभी न)\s*(बताएं|बताएँ|बताए|बताओ|शेयर|दें)",
        r"(otp|ఓటీపీ|పిన్|పాస్‌వర్డ్){S}{0,40}(పంచుకోవద్దు|చెప్పవద్దు|షేర్ చేయవద్దు|ఇవ్వవద్దు|చెప్పకండి|పంచుకోకండి)",
        r"\b(otp|pin)\b{S}{0,25}\b(evvariki|evariki|ewariki)?\s*(share )?(cheyakandi|cheppakandi|ivvakandi|vaddu)\b",
    ], "Genuine banks and apps warn you never to share your OTP or PIN.", []),

    _r("if_not_you", "good", "Says 'if this wasn't you, contact your bank'", 0.35, [
        r"\b(if (this was |it was )?not (you|done by you|initiated by you)|if you did not (make|request|initiate|"
        r"authori[sz]e|do)|not you\?|didn'?t make this|did not make this)\b",
        r"(यदि|अगर) (आपने|यह आपने) (यह )?(नहीं)", r"(మీరు చేయకపోతే)",
    ], "Typical of genuine transaction alerts.", []),

    _r("transaction_alert", "good", "Looks like a normal transaction alert", 0.3, [
        r"\b(debited|credited|spent|withdrawn|paid)\b{S}{0,40}\b(account|card)\s?(xx|\*{2,}|x{2,}|ending( with| in)?)\s?\d{3,4}\b",
        r"\b(account|card)\s?(xx|\*{2,}|x{2,}|ending( with| in)?)\s?\d{3,4}\b{S}{0,40}\b(debited|credited|spent|used)\b",
        r"\bavl\.? ?(balance|limit)\b", r"\bupi ref\b", r"\bref (no\.?|number)\b",
    ], "Normal alerts show a masked account number and don't ask you to do anything.", []),

    _r("known_context", "good", "Normal update about something you did", 0.3, [
        r"\byour (order|booking|appointment|ticket|interview|application)\b{S}{0,40}\b(confirmed|scheduled|shipped|"
        r"delivered|received|is ready|has been)\b",
        r"\bthank you for (your )?(applying|payment|shopping|ordering)\b",
    ], "Routine updates about orders, bookings or applications you made.", []),
]

# Combinations of evidence that are much stronger together than apart (context, not keywords).
CONTEXT_COMBOS: list[tuple[frozenset, float, str]] = [
    (frozenset({"link", "urgency"}), 0.3, "Link + time pressure"),
    (frozenset({"link", "account_threat"}), 0.35, "Link + account threat"),
    (frozenset({"authority", "payment"}), 0.5, "Authority figure demanding money"),
    (frozenset({"prize", "payment"}), 0.45, "Prize that needs a payment"),
    (frozenset({"job_offer", "payment"}), 0.45, "Job that needs a payment"),
    (frozenset({"job_offer", "credential"}), 0.4, "Job asking for documents/credentials"),
    (frozenset({"delivery", "link"}), 0.35, "Parcel problem + link"),
    (frozenset({"delivery", "payment"}), 0.4, "Parcel problem + payment"),
    (frozenset({"utility", "contact"}), 0.4, "Disconnection threat + personal number"),
    (frozenset({"utility", "urgency"}), 0.3, "Disconnection threat + time pressure"),
    (frozenset({"emotional", "payment"}), 0.5, "Emergency + money request"),
    (frozenset({"impersonation", "credential"}), 0.5, "Impersonation + asks for secrets"),
    (frozenset({"impersonation", "account_threat"}), 0.35, "Impersonation + account threat"),
    (frozenset({"gov", "payment"}), 0.45, "Government benefit that needs a payment"),
    (frozenset({"gov", "link"}), 0.3, "Government claim + link"),
    (frozenset({"gov", "credential"}), 0.4, "Government claim + asks for details"),
    (frozenset({"refund", "credential"}), 0.45, "Refund + asks for secrets"),
    (frozenset({"refund", "link"}), 0.3, "Refund + link"),
    (frozenset({"investment", "urgency"}), 0.3, "Investment + time pressure"),
    (frozenset({"account_threat", "urgency"}), 0.3, "Account threat + time pressure"),
    (frozenset({"account_threat", "contact"}), 0.35, "Account threat + personal number"),
    (frozenset({"secrecy", "payment"}), 0.45, "Secrecy + money request"),
    (frozenset({"secrecy", "authority"}), 0.45, "Secrecy + authority threat"),
    (frozenset({"loan", "link"}), 0.3, "Instant loan + link"),
    (frozenset({"loan", "credential"}), 0.4, "Instant loan + asks for details"),
    (frozenset({"injection", "link"}), 0.3, "AI manipulation + link"),
]


@dataclass
class Finding:
    rule_id: str
    kind: str
    name: str
    why: str
    weight: float
    critical: bool
    evidence: str                       # exact words from the message (or normalised form)
    span: tuple[int, int] | None        # position in the ORIGINAL message, for highlighting
    tags: frozenset


def _sentence(text: str, start: int, end: int) -> tuple[int, int]:
    left = max(text.rfind(c, 0, start) for c in ".!?\n।")
    right_candidates = [i for i in (text.find(c, end) for c in ".!?\n।") if i != -1]
    return left + 1, (min(right_candidates) if right_candidates else len(text))


def _negated(text: str, start: int, end: int) -> bool:
    s_start, s_end = _sentence(text, start, end)
    before = text[max(s_start, start - 30):start]
    inside = text[start:end]
    after = text[end:min(s_end, end + 20)]
    return bool(NEG_BEFORE.search(before) or NEG_BEFORE.search(inside) or NEG_AFTER.search(after))


def _locate(original: str, snippet: str) -> tuple[int, int] | None:
    low = original.lower()
    if len(low) != len(original):
        return None
    i = low.find(snippet)
    return (i, i + len(snippet)) if i != -1 else None


def find(original: str, normalized: str) -> list[Finding]:
    """Run every rule on the message. Returns one Finding per rule that fired."""
    targets = [original.lower(), normalized] if original.lower() != normalized else [normalized]
    found: list[Finding] = []
    for rule in RULES:
        hit = None
        for text in targets:
            for rx in rule.compiled:
                for m in rx.finditer(text):
                    if rule.negatable and _negated(text, m.start(), m.end()):
                        continue
                    if rule.exclude_re and rule.exclude_re.search(text):
                        continue  # exclusion applies to the whole message
                    hit = (text, m)
                    break
                if hit:
                    break
            if hit:
                break
        if not hit:
            continue
        text, m = hit
        snippet = m.group(0).strip()
        span = (m.start(), m.end()) if text is targets[0] and targets[0] == original.lower() and len(original) == len(text) \
            else _locate(original, snippet)
        evidence = original[span[0]:span[1]] if span else snippet
        found.append(Finding(rule.id, rule.kind, rule.name, rule.why, rule.weight, rule.critical,
                             evidence, span, rule.tags))
    return found
