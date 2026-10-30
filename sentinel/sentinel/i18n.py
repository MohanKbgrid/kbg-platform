# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Review cards in the reader's language: English and nine Indian languages.

A person's ``language`` in the people configuration (``hi``, ``ta``, ``te``, ``kn``, ``mr``, ``bn``, ``gu``,
``ml``, ``pa``; default English) decides the language of the cards they get on WhatsApp, Slack, Teams, email
and the mobile review page. Fixed words (Approve, Close, Suggested ...) come from the table below. The card's
own text (the exception's description, the reason and the model's rationale) is translated by the model when
one is configured (``task: translate``, so a small or local model can do it), with personal data masked
first, and cached; without a model it stays in English. Facts, codes and action names are never translated:
they are what people search for and talk about.

Native speakers should review the table for each site; ``STRINGS[lang][key] = ...`` in an overlay changes a
word.
"""
from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .engine import Engine

LANGUAGES = {"en": "English", "hi": "हिन्दी", "ta": "தமிழ்", "te": "తెలుగు", "kn": "ಕನ್ನಡ", "mr": "मराठी",
             "bn": "বাংলা", "gu": "ગુજરાતી", "ml": "മലയാളം", "pa": "ਪੰਜਾਬੀ"}
NAMES_EN = {"en": "English", "hi": "Hindi", "ta": "Tamil", "te": "Telugu", "kn": "Kannada", "mr": "Marathi",
            "bn": "Bengali", "gu": "Gujarati", "ml": "Malayalam", "pa": "Punjabi"}

STRINGS: dict[str, dict[str, str]] = {
    "en": {"approve": "Approve", "close": "Close", "close_as": "Close as {code}", "suggested": "Suggested",
           "sure": "{n}% sure", "open": "Open in the console", "due": "due", "nothing": "Nothing waiting for you.",
           "done": "Done", "waiting": "{n} waiting", "then": ", then ", "sign_out": "Sign out"},
    "hi": {"approve": "स्वीकार करें", "close": "बंद करें", "close_as": "बंद करें: {code}", "suggested": "सुझाव",
           "sure": "{n}% निश्चित", "open": "कंसोल में खोलें", "due": "समय-सीमा",
           "nothing": "आपके लिए कुछ भी लंबित नहीं है।", "done": "हो गया", "waiting": "{n} लंबित",
           "then": ", फिर ", "sign_out": "साइन आउट"},
    "ta": {"approve": "ஒப்புதல்", "close": "மூடு", "close_as": "மூடு: {code}", "suggested": "பரிந்துரை",
           "sure": "{n}% உறுதி", "open": "கன்சோலில் திற", "due": "கெடு",
           "nothing": "உங்களுக்காக எதுவும் காத்திருக்கவில்லை.", "done": "முடிந்தது",
           "waiting": "{n} காத்திருக்கின்றன", "then": ", பிறகு ", "sign_out": "வெளியேறு"},
    "te": {"approve": "ఆమోదించు", "close": "మూసివేయి", "close_as": "మూసివేయి: {code}", "suggested": "సూచన",
           "sure": "{n}% ఖచ్చితం", "open": "కన్సోల్‌లో తెరవండి", "due": "గడువు",
           "nothing": "మీ కోసం ఏమీ వేచి లేదు.", "done": "పూర్తయింది", "waiting": "{n} వేచి ఉన్నాయి",
           "then": ", తర్వాత ", "sign_out": "సైన్ అవుట్"},
    "kn": {"approve": "ಅನುಮೋದಿಸಿ", "close": "ಮುಚ್ಚಿ", "close_as": "ಮುಚ್ಚಿ: {code}", "suggested": "ಸಲಹೆ",
           "sure": "{n}% ಖಚಿತ", "open": "ಕನ್ಸೋಲ್‌ನಲ್ಲಿ ತೆರೆಯಿರಿ", "due": "ಗಡುವು",
           "nothing": "ನಿಮಗಾಗಿ ಏನೂ ಕಾಯುತ್ತಿಲ್ಲ.", "done": "ಆಯಿತು", "waiting": "{n} ಕಾಯುತ್ತಿವೆ",
           "then": ", ನಂತರ ", "sign_out": "ಸೈನ್ ಔಟ್"},
    "mr": {"approve": "मंजूर करा", "close": "बंद करा", "close_as": "बंद करा: {code}", "suggested": "सुचवलेले",
           "sure": "{n}% खात्री", "open": "कन्सोलमध्ये उघडा", "due": "मुदत",
           "nothing": "तुमच्यासाठी काहीही प्रलंबित नाही.", "done": "झाले", "waiting": "{n} प्रलंबित",
           "then": ", नंतर ", "sign_out": "साइन आउट"},
    "bn": {"approve": "অনুমোদন করুন", "close": "বন্ধ করুন", "close_as": "বন্ধ করুন: {code}", "suggested": "প্রস্তাব",
           "sure": "{n}% নিশ্চিত", "open": "কনসোলে খুলুন", "due": "সময়সীমা",
           "nothing": "আপনার জন্য কিছুই অপেক্ষমাণ নেই।", "done": "হয়ে গেছে", "waiting": "{n}টি অপেক্ষমাণ",
           "then": ", তারপর ", "sign_out": "সাইন আউট"},
    "gu": {"approve": "મંજૂર કરો", "close": "બંધ કરો", "close_as": "બંધ કરો: {code}", "suggested": "સૂચન",
           "sure": "{n}% ખાતરી", "open": "કન્સોલમાં ખોલો", "due": "સમયમર્યાદા",
           "nothing": "તમારા માટે કંઈ બાકી નથી.", "done": "થઈ ગયું", "waiting": "{n} બાકી",
           "then": ", પછી ", "sign_out": "સાઇન આઉટ"},
    "ml": {"approve": "അംഗീകരിക്കുക", "close": "അടയ്ക്കുക", "close_as": "അടയ്ക്കുക: {code}", "suggested": "നിർദ്ദേശം",
           "sure": "{n}% ഉറപ്പ്", "open": "കൺസോളിൽ തുറക്കുക", "due": "സമയപരിധി",
           "nothing": "നിങ്ങൾക്കായി ഒന്നും കാത്തിരിക്കുന്നില്ല.", "done": "പൂർത്തിയായി",
           "waiting": "{n} കാത്തിരിക്കുന്നു", "then": ", തുടർന്ന് ", "sign_out": "സൈൻ ഔട്ട്"},
    "pa": {"approve": "ਮਨਜ਼ੂਰ ਕਰੋ", "close": "ਬੰਦ ਕਰੋ", "close_as": "ਬੰਦ ਕਰੋ: {code}", "suggested": "ਸੁਝਾਅ",
           "sure": "{n}% ਯਕੀਨੀ", "open": "ਕੰਸੋਲ ਵਿੱਚ ਖੋਲ੍ਹੋ", "due": "ਸਮਾਂ-ਸੀਮਾ",
           "nothing": "ਤੁਹਾਡੇ ਲਈ ਕੁਝ ਵੀ ਬਾਕੀ ਨਹੀਂ ਹੈ।", "done": "ਹੋ ਗਿਆ", "waiting": "{n} ਬਾਕੀ",
           "then": ", ਫਿਰ ", "sign_out": "ਸਾਈਨ ਆਊਟ"},
}


def norm(lang: str | None) -> str:
    code = (lang or "en").strip().lower().replace("_", "-").split("-")[0]
    return code if code in STRINGS else "en"


def t(lang: str | None, key: str, **kw: Any) -> str:
    table = STRINGS[norm(lang)]
    text = table.get(key) or STRINGS["en"][key]
    return text.format(**kw) if kw else text


CACHE = "i18n:{lang}:{h}"
FIELDS = ("title", "reason", "proposal_rationale")


def _client(engine: Engine) -> Any:
    llm = engine.llm
    if llm is None:
        return None
    try:
        return llm.router.client("translate") if llm.router is not None else llm.client
    except LookupError:
        return None


def translate(engine: Engine, texts: list[str], lang: str) -> list[str]:
    """Texts in ``lang`` (cached per text). Any failure leaves a text in English."""
    lang = norm(lang)
    if lang == "en":
        return texts
    out: list[str | None] = []
    todo: dict[int, str] = {}
    for i, s in enumerate(texts):
        if not s or not s.strip():
            out.append(s)
            continue
        h = hashlib.sha256(s.encode()).hexdigest()[:24]
        hit = engine.store.get_source_state(CACHE.format(lang=lang, h=h))
        if hit and isinstance(hit.get("text"), str):
            out.append(hit["text"])
        else:
            out.append(None)
            todo[i] = s
    if todo:
        client = _client(engine)
        done: dict[int, str] = {}
        if client is not None:
            from .routing import PIIMasker, Vault
            vault = Vault()
            masker = engine.masker or PIIMasker()
            masked = {str(i): masker.mask_text(s, vault) for i, s in todo.items()}
            prompt = (f"Translate each value of this JSON object into {NAMES_EN[lang]} for an operations team. Keep "
                      "[PII_n] markers, numbers, codes, ids and words in snake_case exactly as they are. Reply "
                      "with a JSON object with the same keys.\n" + json.dumps(masked, ensure_ascii=False))
            try:
                from .llm import extract_json
                raw = client.complete("You translate short operational messages. Reply with JSON only.",
                                      [{"role": "user", "content": prompt}])
                got = extract_json(raw)
                for k, v in got.items():
                    if k.isdigit() and int(k) in todo and isinstance(v, str) and v.strip():
                        done[int(k)] = PIIMasker.unmask(v, vault)[:2000]
            except Exception:  # noqa: BLE001 - English is a fine fallback
                done = {}
        for i, s in todo.items():
            text = done.get(i)
            if text is not None:
                h = hashlib.sha256(s.encode()).hexdigest()[:24]
                engine.store.put_source_state(CACHE.format(lang=lang, h=h), {"text": text})
            out[i] = text if text is not None else s
    return [x if x is not None else "" for x in out]


def localise(engine: Engine, card: Any) -> Any:
    """The card with its free text in the card's language (``card.language``)."""
    lang = norm(getattr(card, "language", "en"))
    if lang == "en":
        return card
    texts = translate(engine, [getattr(card, f) or "" for f in FIELDS], lang)
    return card.model_copy(update=dict(zip(FIELDS, texts, strict=True)))
