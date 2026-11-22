from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional
from pathlib import Path
import sqlite3, json, random, math, statistics
from datetime import datetime, timedelta, timezone

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "data" / "assetwise.db"
DB.parent.mkdir(exist_ok=True)
app = FastAPI(title="ASSETWISE AI", version="1.0.0",
              description="Research prototype for uncertainty-aware vulnerability prioritisation.")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")

def conn():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    with conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS assets(
          id TEXT PRIMARY KEY, name TEXT, asset_type TEXT, business_function TEXT,
          criticality REAL, internet_exposure INTEGER, network_zone TEXT, owner TEXT,
          updated_at TEXT, source TEXT, status TEXT DEFAULT 'active'
        );
        CREATE TABLE IF NOT EXISTS vulnerabilities(
          cve TEXT PRIMARY KEY, description TEXT, cvss REAL, epss REAL, kev INTEGER,
          product TEXT, asset_id TEXT, status TEXT DEFAULT 'Open'
        );
        CREATE TABLE IF NOT EXISTS reviews(
          id INTEGER PRIMARY KEY AUTOINCREMENT, cve TEXT, asset_id TEXT, action TEXT,
          note TEXT, created_at TEXT
        );
        """)
        if c.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 0:
            now = datetime.now(timezone.utc)
            assets = [
             ("A-001","Payment Gateway","Server","Payment processing",5,1,"DMZ","IT Security",(now-timedelta(days=4)).isoformat(),"SYNTHETIC"),
             ("A-002","Student Portal","Web application","Student services",4,1,"DMZ","Application Team",(now-timedelta(days=100)).isoformat(),"SYNTHETIC"),
             ("A-003","Research Workstation","Workstation","Research computing",3,0,"Internal","Research Lab",(now-timedelta(days=12)).isoformat(),"SYNTHETIC"),
             ("A-004","HR Database","Database","Employee records",5,0,"Restricted","HR IT",(now-timedelta(days=220)).isoformat(),"SYNTHETIC"),
             ("A-005","Library Server","Server","Library services",2,0,"Internal","Library IT",(now-timedelta(days=25)).isoformat(),"SYNTHETIC"),
             ("A-006","VPN Gateway","Network appliance","Remote access",5,1,"DMZ","Network Team",(now-timedelta(days=3)).isoformat(),"SYNTHETIC"),
             ("A-007","Build Server","Server","Software delivery",4,0,"Internal","DevOps",(now-timedelta(days=70)).isoformat(),"SYNTHETIC"),
             ("A-008","IoT Lab Controller","IoT device","Laboratory control",3,0,"OT-Lab","IoT Lab",(now-timedelta(days=15)).isoformat(),"SYNTHETIC")
            ]
            c.executemany("INSERT INTO assets VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                          [(*a,"active") for a in assets])
        if c.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0] == 0:
            rows = [
             ("CVE-2024-3400","Command injection vulnerability in a network security product",10.0,.91,1,"Network appliance","A-006","Open"),
             ("CVE-2023-34362","SQL injection affecting MOVEit Transfer",9.8,.84,1,"File transfer software","A-001","Open"),
             ("CVE-2021-44228","Apache Log4j remote code execution",10.0,.72,1,"Java logging library","A-002","Open"),
             ("CVE-2023-22515","Confluence privilege escalation",9.8,.38,1,"Collaboration software","A-003","Open"),
             ("CVE-2022-22965","Spring Framework remote code execution",9.8,.27,0,"Spring Framework","A-007","Open"),
             ("CVE-2024-21762","Out-of-bounds write in network security product",9.6,.66,1,"Network appliance","A-006","Open"),
             ("CVE-2023-20198","Web UI privilege escalation",10.0,.48,1,"Network appliance","A-008","Open"),
             ("CVE-2022-30190","Microsoft Support Diagnostic Tool vulnerability",7.8,.16,0,"Windows","A-003","Open"),
             ("CVE-2021-34527","Windows Print Spooler remote code execution",8.8,.31,1,"Windows","A-004","Open"),
             ("CVE-2024-3094","XZ Utils backdoor-related vulnerability record",10.0,.02,0,"XZ Utils","A-007","Open"),
             ("CVE-2023-4966","Citrix NetScaler information disclosure",9.4,.73,1,"Network appliance","A-006","Open"),
             ("CVE-2022-1388","F5 BIG-IP authentication bypass",9.8,.89,1,"Network appliance","A-001","Open")
            ]
            c.executemany("INSERT INTO vulnerabilities VALUES(?,?,?,?,?,?,?,?)", rows)

def rows(table):
    with conn() as c:
        return [dict(r) for r in c.execute(f"SELECT * FROM {table}").fetchall()]

def quality(a):
    now = datetime.now(timezone.utc)
    try: age = (now - datetime.fromisoformat(a["updated_at"])).days
    except: age = 9999
    issues=[]
    if a["criticality"] is None: issues.append("missing criticality")
    if a["internet_exposure"] is None: issues.append("missing exposure")
    if age > 90: issues.append(f"stale ({age} days)")
    # Demonstration conflict flag for one synthetic record, explicitly labelled.
    if a["id"] == "A-004": issues.append("synthetic source conflict")
    return {"age_days":age,"issues":issues,"quality":"COMPLETE" if not issues else "UNRELIABLE"}

def base_score(v, a, mode="assetwise", criticality=None, exposure=None):
    crit = a["criticality"] if criticality is None else criticality
    exp = a["internet_exposure"] if exposure is None else exposure
    cv = float(v["cvss"] or 0)/10
    ep = float(v["epss"] or 0)
    kev = 1 if v["kev"] else 0
    if mode=="cvss": return cv*100
    if mode=="epss": return ep*100
    if mode=="kev": return kev*100 + cv*10
    if mode=="combined": return 40*cv + 35*ep + 25*kev
    # Transparent illustrative context score; not an industry standard.
    c = (float(crit or 3)-1)/4
    e = float(exp or 0)
    return 30*cv + 25*ep + 20*kev + 15*c + 10*e

def rankings(mode="assetwise"):
    assets={a["id"]:a for a in rows("assets")}
    out=[]
    for v in rows("vulnerabilities"):
        a=assets.get(v["asset_id"])
        if not a: continue
        out.append({**v,"asset_name":a["name"],"score":round(base_score(v,a,mode),3)})
    return sorted(out,key=lambda x:x["score"],reverse=True)

def run_simulation(degradation=0.3, scenarios=100, seed=42, top_k=5, defect="mixed"):
    rng=random.Random(seed)
    assets={a["id"]:a for a in rows("assets")}
    vulns=rows("vulnerabilities")
    scenario_ranks={v["cve"]:[] for v in vulns}
    modes=["missing","stale","conflict"] if defect=="mixed" else [defect]
    for s in range(scenarios):
        changed={}
        for aid,a in assets.items():
            crit=a["criticality"]; exp=a["internet_exposure"]
            if rng.random()<degradation:
                m=rng.choice(modes)
                if m=="missing":
                    if rng.random()<.5: crit=None
                    else: exp=None
                elif m=="stale":
                    # Simulate an old value by using a plausible alternate value.
                    if rng.random()<.5: crit=max(1,min(5,(crit or 3)+rng.choice([-2,-1,1,2])))
                    else: exp=1-(exp or 0)
                else:
                    # Conflicting source value; choose a plausible conflicting value.
                    crit=rng.choice([1,2,4,5])
                    exp=rng.choice([0,1])
            changed[aid]=(crit,exp)
        ranked=[]
        for v in vulns:
            a=assets[v["asset_id"]]
            crit,exp=changed[v["asset_id"]]
            # Missing context uses neutral midpoint, while quality flag is separately retained.
            score=base_score(v,a,"assetwise",crit if crit is not None else 3,
                             exp if exp is not None else 0.5)
            ranked.append((v["cve"],score))
        ranked.sort(key=lambda x:x[1],reverse=True)
        for i,(cve,score) in enumerate(ranked,1):
            scenario_ranks[cve].append(i)
    baseline={r["cve"]:r["score"] for r in rankings("assetwise")}
    result=[]
    for cve,rs in scenario_ranks.items():
        in_top=sum(1 for r in rs if r<=top_k)
        result.append({"cve":cve,"top_k_probability":round(in_top/scenarios,3),
                       "median_rank":round(statistics.median(rs),2),
                       "min_rank":min(rs),"max_rank":max(rs),
                       "rank_std":round(statistics.pstdev(rs),3),
                       "baseline_score":baseline.get(cve)})
    result.sort(key=lambda x:(-x["top_k_probability"],x["median_rank"]))
    return {"seed":seed,"scenarios":scenarios,"degradation":degradation,
            "top_k":top_k,"defect":defect,"results":result,
            "note":"Synthetic scenario experiment. Empirical scenario ranges are not calibrated confidence intervals."}

class ReviewIn(BaseModel):
    cve: str
    asset_id: str
    action: str
    note: str = ""

class AssetIn(BaseModel):
    id: str
    name: str
    asset_type: str = "Server"
    business_function: str = "General"
    criticality: Optional[float] = 3
    internet_exposure: Optional[int] = 0
    network_zone: str = "Internal"
    owner: str = "Unassigned"
    updated_at: Optional[str] = None
    source: str = "SYNTHETIC"

@app.on_event("startup")
def startup(): init_db()

@app.get("/", response_class=HTMLResponse)
def home():
    return (ROOT / "static" / "index.html").read_text(encoding="utf-8")

@app.get("/api/health")
def health(): return {"status":"ok","app":"ASSETWISE AI","version":"1.0.0"}

@app.get("/api/assets")
def get_assets():
    data=rows("assets")
    for a in data: a["data_quality"]=quality(a)
    return data

@app.post("/api/assets")
def add_asset(a:AssetIn):
    with conn() as c:
        try:
            c.execute("INSERT INTO assets VALUES(?,?,?,?,?,?,?,?,?,?,?)",
             (a.id,a.name,a.asset_type,a.business_function,a.criticality,a.internet_exposure,
              a.network_zone,a.owner,a.updated_at or datetime.now(timezone.utc).isoformat(),a.source,"active"))
        except sqlite3.IntegrityError: raise HTTPException(409,"Asset ID already exists")
    return {"created":a.id}

@app.get("/api/vulnerabilities")
def get_vulns(): return rankings("assetwise")

@app.get("/api/rankings")
def get_rankings():
    return {m:rankings(m) for m in ["cvss","epss","kev","combined","assetwise"]}

@app.get("/api/summary")
def summary():
    a=rows("assets"); v=rows("vulnerabilities")
    q=[quality(x) for x in a]
    sim=run_simulation(.3,60,42,5)
    return {"assets":len(a),"vulnerabilities":len(v),
      "critical":sum(1 for x in v if x["cvss"]>=9),
      "kev":sum(1 for x in v if x["kev"]),
      "unreliable_assets":sum(1 for x in q if x["quality"]!="COMPLETE"),
      "pending_reviews":len([x for x in sim["results"] if x["top_k_probability"]<.7 and x["baseline_score"]>=55])}

@app.get("/api/simulate")
def simulate(degradation:float=.3,scenarios:int=100,seed:int=42,top_k:int=5,defect:str="mixed"):
    if not 0<=degradation<=1: raise HTTPException(400,"degradation must be between 0 and 1")
    if not 10<=scenarios<=2000: raise HTTPException(400,"scenarios must be 10..2000")
    if defect not in ["mixed","missing","stale","conflict"]: raise HTTPException(400,"invalid defect type")
    return run_simulation(degradation,scenarios,seed,top_k,defect)

@app.get("/api/reviews")
def get_reviews(): return rows("reviews")

@app.post("/api/reviews")
def add_review(r:ReviewIn):
    if r.action not in ["Approve","Reject","Request verification"]: raise HTTPException(400,"Invalid action")
    with conn() as c:
        c.execute("INSERT INTO reviews(cve,asset_id,action,note,created_at) VALUES(?,?,?,?,?)",
          (r.cve,r.asset_id,r.action,r.note,datetime.now(timezone.utc).isoformat()))
    return {"saved":True}

@app.get("/api/experiments")
def experiments():
    sims=[run_simulation(d,100,42,5,"mixed") for d in [.0,.1,.2,.3,.5]]
    return [{"degradation":s["degradation"],"mean_rank_std":round(statistics.mean(x["rank_std"] for x in s["results"]),3),
             "mean_topk_probability":round(statistics.mean(x["top_k_probability"] for x in s["results"]),3)}
            for s in sims]
