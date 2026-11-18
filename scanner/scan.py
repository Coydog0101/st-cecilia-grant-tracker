#!/usr/bin/env python3
"""Grant-opportunity scan for the St. Cecilia grant dashboard.

Runs every other Monday morning from .github/workflows/grant-scan.yml. It:
  1. decrypts the previous results (docs/data/grants.enc.json),
  2. searches Grants.gov,
  3. checks each page in scanner/sources.json -> watch_pages and (with AI on)
     pulls the opportunities and deadlines out of the page,
  4. (with AI on) asks Claude to search the web for NEW opportunities,
  5. merges everything and writes it back encrypted with the dashboard password.

Environment:
  DASHBOARD_PASSWORD      required - the shared password people type into the dashboard
  GH_DATA_TOKEN           fine-grained GitHub token (Contents: read/write on this repo),
                          handed to the dashboard *inside the encrypted file* so it can
                          save Apply/Decline decisions
  ANTHROPIC_API_KEY       optional - enables the AI steps
  OLD_DASHBOARD_PASSWORD  optional - set once when changing the password so existing
                          data and decisions are re-encrypted instead of lost

Usage: python scanner/scan.py [--no-ai]
"""
import datetime as dt
import hashlib
import html
import json
import os
import re
import sys
import urllib.error
import urllib.request
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin

sys.path.insert(0, str(Path(__file__).resolve().parent))
from crypto_util import DecryptError, decrypt_json, encrypt_json  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "docs" / "data"
GRANTS_FILE = DATA_DIR / "grants.enc.json"
DECISIONS_FILE = DATA_DIR / "decisions.enc.json"
CONFIG = json.loads((Path(__file__).resolve().parent / "sources.json").read_text("utf-8"))
USER_AGENT = "Mozilla/5.0 (compatible; SchoolGrantTracker/1.0)"
TODAY = dt.date.today()
NOW = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
REEXTRACT_DAYS = 14         # re-read an unchanged watch page with AI at least this often
PRUNE_AFTER_DAYS = 365      # drop undecided items whose deadline passed this long ago
MAX_PAGE_CHARS = 40_000


def log(*args):
    print(*args, flush=True)


# --------------------------------------------------------------------------- helpers

def http(url, payload=None, timeout=40):
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    body = None
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        charset = resp.headers.get_content_charset() or "utf-8"
        return resp.read().decode(charset, errors="replace")


class _PageText(HTMLParser):
    SKIP = {"script", "style", "noscript", "svg", "template"}
    BLOCK = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "section", "article", "table", "ul", "ol"}

    def __init__(self, base):
        super().__init__(convert_charrefs=True)
        self.base, self.parts, self.skip, self.href = base, [], 0, None

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self.skip += 1
        elif tag in self.BLOCK:
            self.parts.append("\n")
        elif tag == "a":
            self.href = dict(attrs).get("href")

    def handle_endtag(self, tag):
        if tag in self.SKIP and self.skip:
            self.skip -= 1
        elif tag == "a":
            if self.href and not self.href.startswith(("#", "javascript:", "mailto:", "tel:")) and not self.skip:
                self.parts.append(f" <{urljoin(self.base, self.href)}>")
            self.href = None

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)


def page_text(html_src, base):
    parser = _PageText(base)
    parser.feed(html_src)
    text = "".join(parser.parts)
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n", text)
    return text.strip()[:MAX_PAGE_CHARS]


def norm(s):
    return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()


def make_id(funder, title):
    return hashlib.sha1(f"{norm(funder)}|{norm(title)}".encode()).hexdigest()[:12]


def parse_date(value):
    """Accept YYYY-MM-DD or MM/DD/YYYY; return ISO string or ''."""
    value = (value or "").strip()
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%b %d, %Y"):
        try:
            return dt.datetime.strptime(value, fmt).date().isoformat()
        except ValueError:
            pass
    return ""


def strip_tags(s):
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", s or ""))).strip()


# --------------------------------------------------------------------------- Claude

OPPORTUNITY_SCHEMA = {
    "type": "object",
    "properties": {
        "title": {"type": "string", "description": "Name of the grant / program"},
        "funder": {"type": "string"},
        "url": {"type": "string", "description": "Official page with details or the application"},
        "amount": {"type": "string", "description": "Award size, e.g. 'Up to $15,000'; '' if not stated"},
        "deadline": {"type": "string", "description": "Next deadline on or after today as YYYY-MM-DD, or '' if none is published"},
        "deadline_note": {"type": "string", "description": "e.g. 'Rolling', 'Cycle 1 of 3', '2027 dates not yet posted (2026 cycles: Feb 20, Jun 19, Sep 18)'"},
        "description": {"type": "string", "description": "2-5 plain sentences on what it funds and how to apply"},
        "eligibility": {"type": "string", "description": "Who can apply, geography, restrictions"},
        "fit": {"type": "string", "description": "One sentence summary of how well it suits this school"},
        "grade_levels": {"type": "string", "description": "Grades the program serves, e.g. 'PreK-8', 'K-5', 'K-12', 'Grades 6-12'"},
        "fit_score": {"type": "integer", "description": "1-5: 5 = built for PreK-8 schools and open to private/Catholic schools; 4 = K-12 and clearly open to private schools; 3 = possibly eligible, needs checking; 2 = unlikely; 1 = not eligible"},
        "pros": {"type": "string", "description": "2-4 reasons St. Cecilia is a strong candidate, one per line starting with '- '"},
        "cons": {"type": "string", "description": "1-4 reasons it might not be a fit, risks, or things to verify (eligibility of private/religious schools, match requirements, competitiveness, effort), one per line starting with '- '"},
        "category": {"type": "string", "description": "One of: Technology, STEM, Literacy & Library, Music & Arts, Safety & Security, Facilities & Capital, Playground & Health, Teachers, Tuition & Scholarships, Faith Formation, General Operating, Other"},
    },
    "required": ["title", "funder", "url", "amount", "deadline", "deadline_note", "description", "eligibility",
                 "fit", "grade_levels", "fit_score", "pros", "cons", "category"],
    "additionalProperties": False,
}
CATEGORIES = ("Technology, STEM, Literacy & Library, Music & Arts, Safety & Security, Facilities & Capital, "
              "Playground & Health, Teachers, Tuition & Scholarships, Faith Formation, General Operating, Other")
FIT_RULES = """How to judge fit for THIS school (a private Catholic PreK-8 school):
- It must serve students somewhere in PreK-8th grade. Programs only for high schools, colleges, universities, adults, or researchers do NOT fit.
- The school (or its diocese/parish on its behalf, or one of its teachers) must be able to apply. Many programs are limited to public schools, districts, or Title I schools, or exclude religious organizations - those do not fit unless the rules clearly allow private or Catholic schools.
- fit_score: 5 = built for PreK-8/elementary schools and open to private or Catholic schools; 4 = K-12 and clearly open to private schools; 3 = possibly eligible but needs checking; 2 = unlikely; 1 = not eligible.
- pros: concrete reasons we are a strong candidate (location, Catholic identity, grade levels, matching needs). cons: honest reasons we might not be (eligibility doubts, match or reporting requirements, very competitive, small award vs. effort, timing)."""
OPPORTUNITY_LIST_SCHEMA = {
    "type": "object",
    "properties": {"opportunities": {"type": "array", "items": OPPORTUNITY_SCHEMA}},
    "required": ["opportunities"],
    "additionalProperties": False,
}


def claude(prompt, *, schema=None, web=False, light=False, max_tokens=32000):
    """light=True uses the cheap model for simple reading/screening jobs."""
    import anthropic

    ai = CONFIG["ai"]
    model = ai.get("light_model", "claude-haiku-5-5") if light else ai.get("model", "claude-sonnet-5-5")
    effort = ai.get("light_effort", "low") if light else ai.get("effort", "medium")
    output_config = {"effort": effort}
    if schema:
        output_config["format"] = {"type": "json_schema", "schema": schema}
    kwargs = dict(
        model=model,
        max_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}],
        output_config=output_config,
    )
    is_haiku = "haiku" in model
    if not is_haiku:
        # Server-side fallback if a safety classifier wrongly declines (not offered on Haiku).
        kwargs["betas"] = ["server-side-fallback-2026-07-01"]
        kwargs["fallbacks"] = "default"
    if web:
        kwargs["tools"] = [{
            # Haiku uses the basic web search tool; Sonnet/Opus get the newer filtered one.
            "type": "web_search_20250305" if is_haiku else "web_search_20260209",
            "name": "web_search",
            "max_uses": int(ai.get("web_searches_per_area", 6)),
        }]

    client = anthropic.Anthropic()
    for _ in range(8):
        with client.beta.messages.stream(**kwargs) as stream:
            resp = stream.get_final_message()
        if resp.stop_reason == "pause_turn":  # long web-search turn; let it continue
            kwargs["messages"] = kwargs["messages"] + [{"role": "assistant", "content": resp.content}]
            continue
        break
    if resp.stop_reason == "refusal":
        raise RuntimeError("Claude declined the request")
    if resp.stop_reason == "max_tokens":
        raise RuntimeError("Claude's answer was cut off (max_tokens)")
    return "".join(b.text for b in resp.content if b.type == "text")


def extract_json(text):
    blocks = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.S)
    candidate = blocks[-1] if blocks else text[text.find("{"): text.rfind("}") + 1]
    return json.loads(candidate)


def school():
    return CONFIG["school_profile"]


def ai_extract_page(funder, url, text):
    prompt = f"""Today is {TODAY.isoformat()}.

The school: {school()}

Below is the text of a grants page from {funder} ({url}). Links appear as <url>.
List every distinct grant, funding program or sponsorship on this page that this school could realistically apply for.

{FIT_RULES}

Rules:
- deadline: the NEXT deadline on or after today, as YYYY-MM-DD. If every date shown is in the past and the next one is not posted, leave it '' and summarize past dates in deadline_note. If applications are accepted any time, leave it '' and put 'Rolling' in deadline_note.
- url: the most specific official link (application or program page) from the page; otherwise {url}.
- funder: "{funder}" unless the page clearly names a different funder for that program.
- Leave a field '' rather than guess. Omit programs with fit_score 1 (e.g. individuals only, wrong region, high school/college only).
- category: one of {CATEGORIES}.
- Return an empty list if the page has no applicable opportunities.

PAGE TEXT:
{text}"""
    return json.loads(claude(prompt, schema=OPPORTUNITY_LIST_SCHEMA, light=True, max_tokens=16000))["opportunities"]


def todays_areas():
    """Areas to search this run. With areas_per_run < number of areas, rotate each scan week."""
    ai = CONFIG["ai"]
    areas = ai.get("search_areas", [])
    if not areas:
        return []
    per_run = max(1, min(int(ai.get("areas_per_run", len(areas))), len(areas)))
    start = ((TODAY.toordinal() // 7) * per_run) % len(areas)
    return [areas[(start + i) % len(areas)] for i in range(per_run)]


def ai_discover(area, known):
    ai = CONFIG["ai"]
    known_lines = "\n".join(f"- {g['funder']}: {g['title']}" for g in known[:250]) or "- (none yet)"
    example = {k: "" for k in OPPORTUNITY_SCHEMA["required"]}
    example["fit_score"] = 4
    prompt = f"""Today is {TODAY.isoformat()}. You are helping a parent volunteer find grant funding for a school.

The school: {school()}

Search area for this run: {area['name']}
{area['focus']}

Search the web thoroughly within this area for grant or funding opportunities this school could apply for that are currently open, opening in the next few months, recurring every year, or accepting applications on a rolling basis. Try several different searches (funder names, "grant" + "Catholic school", "private school eligible", "elementary school grant Louisiana", etc.) and open the funders' own pages to confirm.

{FIT_RULES}

Already tracked - do NOT repeat these:
{known_lines}

Requirements:
- Only include opportunities with fit_score 3 or higher.
- Confirm details on the funder's official site and use that page as url. Skip anything you cannot confirm. Skip one-time programs that have ended with no next cycle.
- deadline: the next deadline on or after today as YYYY-MM-DD, else '' (explain in deadline_note, e.g. 'Rolling', 'Opens each January', '2027 dates not yet posted').
- category: one of {CATEGORIES}.
- Up to 12 new opportunities.

When you are done searching, finish your reply with ONE fenced ```json block containing an object of the form
{{"opportunities": [{json.dumps(example)}]}}"""
    return extract_json(claude(prompt, web=True, max_tokens=48000)).get("opportunities", [])


def ai_screen_federal(hits):
    item = {k: v for k, v in OPPORTUNITY_SCHEMA["properties"].items()
            if k in ("fit", "grade_levels", "fit_score", "pros", "cons", "category")}
    schema = {
        "type": "object",
        "properties": {"keep": {"type": "array", "items": {
            "type": "object",
            "properties": {"id": {"type": "string"}, **item},
            "required": ["id", *item.keys()], "additionalProperties": False}}},
        "required": ["keep"], "additionalProperties": False,
    }
    listing = "\n\n".join(
        f"id: {h['id']}\ntitle: {h['title']}\nagency: {h['funder']}\neligibility: {h['eligibility'][:500]}\nsummary: {h['description'][:800]}"
        for h in hits)
    prompt = f"""The school: {school()}

These are federal opportunities from Grants.gov. Most federal grants go to states, districts, universities, researchers or large nonprofits and should be dropped.

{FIT_RULES}

Return ONLY the items with fit_score 3 or higher, with fit, grade_levels, fit_score, pros, cons and category (one of {CATEGORIES}). Returning an empty list is fine.

{listing}"""
    return {k["id"]: k for k in json.loads(claude(prompt, schema=schema, light=True, max_tokens=16000))["keep"]}


# --------------------------------------------------------------------------- sources

def grants_gov(state, ai_on, report):
    cfg = CONFIG.get("grants_gov", {})
    if not cfg.get("enabled"):
        return []
    rejected = set(state.setdefault("gg_rejected", []))
    known = set(state.get("known_ids", []))
    hits = {}
    for kw in cfg.get("keywords", []):
        try:
            res = json.loads(http("https://api.grants.gov/v1/api/search2", {
                "keyword": kw, "oppStatuses": "forecasted|posted",
                "eligibilities": cfg.get("eligibilities", ""), "rows": cfg.get("max_results_per_keyword", 25)}))
            for h in (res.get("data") or {}).get("oppHits", []):
                hits[str(h["id"])] = h
        except Exception as exc:
            report.append({"name": f"Grants.gov '{kw}'", "status": "error", "detail": str(exc)[:200]})
    new = [h for oid, h in hits.items() if f"gg-{oid}" not in known and oid not in rejected]
    log(f"Grants.gov: {len(hits)} hits, {len(new)} new to review")

    items = []
    for h in new[:100]:
        oid = str(h["id"])
        desc, elig, amount, url = "", "", "", f"https://www.grants.gov/search-results-detail/{oid}"
        try:
            detail = json.loads(http("https://api.grants.gov/v1/api/fetchOpportunity", {"opportunityId": int(oid)}))
            syn = ((detail.get("data") or {}).get("synopsis") or (detail.get("data") or {}).get("forecast") or {})
            desc = strip_tags(syn.get("synopsisDesc") or syn.get("forecastDesc"))[:2500]
            elig = strip_tags(syn.get("applicantEligibilityDesc"))[:1200]
            ceiling = syn.get("awardCeilingFormatted") or syn.get("awardCeiling")
            amount = f"Up to ${ceiling}" if ceiling and str(ceiling) not in ("0", "none", "None") else ""
        except Exception as exc:
            log(f"  detail failed for {oid}: {exc}")
        items.append({
            "id": f"gg-{oid}", "title": h.get("title", ""), "funder": h.get("agency") or h.get("agencyName") or h.get("agencyCode", "Federal agency"),
            "url": url, "amount": amount, "deadline": parse_date(h.get("closeDate")),
            "deadline_note": "Forecasted - dates may change" if h.get("oppStatus") == "forecasted" else "",
            "description": desc, "eligibility": elig, "fit": "", "category": "Other", "source": "Grants.gov",
        })

    if not ai_on:
        # Without AI, use a simple keyword screen so the list stays about PreK-8 schools.
        k8 = re.compile(r"\b(k-?12|k-?8|elementary|middle school|pre-?k|preschool|early childhood|schools?|children|youth)\b", re.I)
        higher_ed = re.compile(r"\b(undergraduate|graduate|postsecondary|higher education|universit\w*|colleges?|research|fellowship|clinical)\b", re.I)
        items = [it for it in items
                 if k8.search(f"{it['title']} {it['description'][:800]}") and not higher_ed.search(it["title"])]
    if ai_on and items:
        try:
            keep = ai_screen_federal(items)
            for it in items:
                if it["id"] in keep:
                    it.update({k: v for k, v in keep[it["id"]].items() if k != "id"})
                else:
                    rejected.add(it["id"][3:])
            items = [it for it in items if it["id"] in keep]
            log(f"  AI kept {len(items)} federal opportunities")
        except Exception as exc:
            report.append({"name": "Grants.gov AI screening", "status": "error", "detail": str(exc)[:200]})
    state["gg_rejected"] = sorted(rejected)[-2000:]
    report.append({"name": "Grants.gov", "status": "ok", "detail": f"{len(hits)} matches, {len(items)} new added"})
    return items


def watch_pages(state, ai_on, report):
    pages = state.setdefault("pages", {})
    items = []
    for page in CONFIG.get("watch_pages", []):
        url, funder = page["url"], page["funder"]
        prev = pages.get(url, {})
        try:
            text = page_text(http(url), url)
        except Exception as exc:
            report.append({"name": funder, "url": url, "status": "error", "detail": f"Could not load page: {str(exc)[:160]}"})
            continue
        digest = hashlib.sha256(text.encode()).hexdigest()
        changed = digest != prev.get("hash")
        last_ai = prev.get("ai_checked", "")
        stale = not last_ai or (TODAY - dt.date.fromisoformat(last_ai[:10])).days >= REEXTRACT_DAYS
        entry = {"hash": digest, "checked": NOW, "changed_at": NOW if changed else prev.get("changed_at", NOW),
                 "ai_checked": last_ai}

        if ai_on and (changed or stale):
            try:
                found = ai_extract_page(funder, url, text)
                for o in found:
                    o["source"] = "Watched page"
                    o["source_page"] = url
                items.extend(found)
                entry["ai_checked"] = NOW
                report.append({"name": funder, "url": url, "status": "changed" if changed and prev else "ok",
                               "detail": f"{len(found)} opportunities read from page"})
            except Exception as exc:
                report.append({"name": funder, "url": url, "status": "error", "detail": f"AI read failed: {str(exc)[:160]}"})
        elif not ai_on:
            # Without AI, track the page itself as one opportunity and flag changes.
            items.append({
                "id": "page-" + hashlib.sha1(url.encode()).hexdigest()[:10],
                "title": f"{funder} - grant page", "funder": funder, "url": url, "amount": "", "deadline": "",
                "deadline_note": "Page changed - check for new dates" if changed and prev else "Check page for dates",
                "description": text[:1200], "eligibility": "", "fit": "", "category": "Other",
                "source": "Watched page", "source_page": url})
            report.append({"name": funder, "url": url, "status": "changed" if changed and prev else "ok",
                           "detail": "Page changed since last check" if changed and prev
                           else ("No change since last check" if prev else "First check")})
        else:
            report.append({"name": funder, "url": url, "status": "ok", "detail": "No change since last check"})
        pages[url] = entry
    return items


# --------------------------------------------------------------------------- merge / io

FIELDS = ["title", "funder", "url", "amount", "deadline", "deadline_note", "description", "eligibility",
          "fit", "grade_levels", "pros", "cons", "category"]


def merge(existing, found, source_default):
    added = 0
    min_fit = int(CONFIG.get("ai", {}).get("min_fit_score", 3))
    for o in found:
        if not (o.get("title") and o.get("funder")):
            continue
        try:
            score = int(o.get("fit_score") or 0)
        except (TypeError, ValueError):
            score = 0
        if score and score < min_fit:      # AI judged it a poor fit for a PreK-8 Catholic school
            continue
        o["deadline"] = parse_date(o.get("deadline", ""))
        gid = o.get("id") or make_id(o["funder"], o["title"])
        cur = existing.get(gid)
        if cur is None:
            cur = {"id": gid, "first_seen": NOW, "source": o.get("source", source_default)}
            existing[gid] = cur
            added += 1
        elif cur.get("deadline") != o["deadline"] and o["deadline"]:
            cur["updated"] = NOW
        for f in FIELDS:
            if o.get(f):
                cur[f] = str(o[f]).strip()
            cur.setdefault(f, "")
        if score:
            cur["fit_score"] = score
        if o.get("source_page"):
            cur["source_page"] = o["source_page"]
        cur["last_seen"] = NOW
    return added


def load_encrypted(path, password, old_password):
    if not path.exists():
        return None, False
    env = json.loads(path.read_text("utf-8"))
    try:
        return decrypt_json(env, password), False
    except DecryptError:
        if old_password:
            try:
                return decrypt_json(env, old_password), True
            except DecryptError:
                pass
        log(f"WARNING: could not decrypt {path.name} with the current password")
        return None, False


def write_encrypted(path, obj, password):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(encrypt_json(obj, password), indent=0) + "\n", "utf-8")


def main():
    password = os.environ.get("DASHBOARD_PASSWORD", "")
    if len(password) < 8:
        sys.exit("DASHBOARD_PASSWORD must be set (8+ characters).")
    old_password = os.environ.get("OLD_DASHBOARD_PASSWORD", "")
    ai_on = CONFIG.get("ai", {}).get("enabled", False) and bool(os.environ.get("ANTHROPIC_API_KEY")) and "--no-ai" not in sys.argv
    log(f"Scan {NOW} - AI {'on' if ai_on else 'off'}")

    prev, _ = load_encrypted(GRANTS_FILE, password, old_password)
    prev = prev or {}
    state = prev.get("state", {})
    grants = {g["id"]: g for g in prev.get("grants", [])}
    state["known_ids"] = list(grants)
    report = []

    added = merge(grants, grants_gov(state, ai_on, report), "Grants.gov")
    added += merge(grants, watch_pages(state, ai_on, report), "Watched page")
    if ai_on:
        for area in todays_areas():
            name = f"AI web search: {area['name']}"
            try:
                known = sorted(grants.values(), key=lambda g: g.get("first_seen", ""), reverse=True)
                found = ai_discover(area, known)
                for o in found:
                    o["source"] = "AI web search"
                n = merge(grants, found, "AI web search")
                added += n
                report.append({"name": name, "status": "ok", "detail": f"{len(found)} found, {n} new"})
                state.setdefault("areas_searched", {})[area["name"]] = NOW
            except Exception as exc:
                report.append({"name": name, "status": "error", "detail": str(exc)[:200]})
    else:
        report.append({"name": "AI web search", "status": "off", "detail": "Add the ANTHROPIC_API_KEY secret to turn this on"})

    # Decisions: re-key on password change, and never prune an item someone has decided on.
    decisions, rekeyed = load_encrypted(DECISIONS_FILE, password, old_password)
    if rekeyed:
        write_encrypted(DECISIONS_FILE, decisions, password)
        log("Re-encrypted decisions with the new password")
    decided = set(((decisions or {}).get("decisions") or {}).keys())
    cutoff = (TODAY - dt.timedelta(days=PRUNE_AFTER_DAYS)).isoformat()
    for gid in [g for g, v in grants.items() if v.get("deadline") and v["deadline"] < cutoff and g not in decided]:
        del grants[gid]
    state.pop("known_ids", None)

    runs = (prev.get("runs") or [])[-29:] + [{"at": NOW, "added": added, "errors": sum(r["status"] == "error" for r in report)}]
    repo = os.environ.get("GITHUB_REPOSITORY", os.environ.get("DASHBOARD_REPO", ""))
    payload = {
        "generated_at": NOW,
        "ai": ai_on,
        "github": {
            "repo": repo,
            "branch": os.environ.get("GITHUB_REF_NAME", "main"),
            "token": os.environ.get("GH_DATA_TOKEN", ""),
            "decisions_path": "docs/data/decisions.enc.json",
        },
        "grants": sorted(grants.values(), key=lambda g: (g.get("deadline") or "9999", g["title"])),
        "sources": report,
        "runs": runs,
        "state": state,
    }
    write_encrypted(GRANTS_FILE, payload, password)
    log(f"Done: {len(grants)} opportunities tracked, {added} new.")
    for r in report:
        log(f"  [{r['status']}] {r['name']}: {r.get('detail', '')}")


if __name__ == "__main__":
    main()
