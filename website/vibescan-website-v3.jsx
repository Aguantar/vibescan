import { useState, useEffect, useRef } from "react";

const FAQS = [
  { q: "VibeScan은 무엇인가요?", a: "VibeScan은 바이브코딩 시대에 맞춘 로컬 코드 보안 점검 도구입니다. AI가 생성한 코드에서 민감정보 노출, 보안 취약점, 설정 실수를 탐지하고 초보자도 이해할 수 있는 설명형 리포트를 제공합니다." },
  { q: "누구를 위한 도구인가요?", a: "ChatGPT, Claude, Cursor 등으로 코드를 생성하는 바이브코더, GitHub에 포트폴리오를 공개하는 주니어 개발자, 프로그래밍을 배우고 있는 학습자를 위해 설계되었습니다." },
  { q: "코드가 외부로 전송되나요?", a: "절대 아닙니다. VibeScan은 100% 로컬에서 동작합니다. 네트워크 통신 자체가 없으며 오프라인에서도 동일하게 작동합니다." },
  { q: "어떤 리포트 형식을 지원하나요?", a: "콘솔 컬러 출력, JSON 리포트(CI/CD 연동용), HTML 시각 리포트 세 가지 형식을 지원합니다. CRITICAL/HIGH 발견 시 exit code 1을 반환합니다." },
  { q: "어떤 언어를 지원하나요?", a: "Python과 JavaScript/TypeScript의 코드 패턴을 분석합니다. Secret 탐지와 Git Hygiene은 언어 무관하게 모든 프로젝트에서 동작합니다." },
];

const RULES = [
  { id: "SEC001", name: "Hardcoded Secret", sev: "CRITICAL", desc: "API 키, 비밀번호, 토큰이 코드에 직접 입력됨" },
  { id: "SEC002", name: "Env File Exposed", sev: "CRITICAL", desc: ".env 파일이 .gitignore에 등록되지 않음" },
  { id: "SEC003", name: "Service Account Key", sev: "CRITICAL", desc: "클라우드 서비스 인증 파일이 프로젝트에 포함됨" },
  { id: "SEC004", name: "Private Key File", sev: "CRITICAL", desc: "SSH 키 또는 인증서 개인키가 포함됨" },
  { id: "SEC005", name: "SQL Injection", sev: "CRITICAL", desc: "사용자 입력이 SQL 쿼리에 직접 삽입됨" },
  { id: "SEC006", name: "Connection String", sev: "CRITICAL", desc: "DB 연결 문자열에 비밀번호 포함" },
  { id: "PAT001", name: "Dangerous Function", sev: "HIGH", desc: "eval(), exec() 등 임의 코드 실행 함수" },
  { id: "PAT002", name: "XSS Vulnerability", sev: "HIGH", desc: "innerHTML, dangerouslySetInnerHTML 사용" },
  { id: "PAT003", name: "Shell Injection", sev: "HIGH", desc: "subprocess(shell=True), os.system() 사용" },
  { id: "PAT004", name: "Frontend Secret", sev: "HIGH", desc: "NEXT_PUBLIC_, VITE_ 환경변수에 시크릿" },
  { id: "PAT005", name: "JWT No Verify", sev: "HIGH", desc: "jwt.decode만 사용, verify 누락" },
  { id: "GIT001", name: "No Gitignore", sev: "HIGH", desc: ".gitignore 파일이 존재하지 않음" },
  { id: "CFG001", name: "Debug Mode", sev: "MEDIUM", desc: "DEBUG = True 활성화 상태" },
  { id: "CFG002", name: "CORS Allow All", sev: "MEDIUM", desc: "CORS origin이 *로 설정됨" },
  { id: "CFG003", name: "SSL Verify Off", sev: "MEDIUM", desc: "verify=False로 SSL 검증 비활성화" },
  { id: "STR002", name: "No Env Example", sev: "MEDIUM", desc: ".env.example 파일이 없음" },
  { id: "STR003", name: "Unfixed Deps", sev: "MEDIUM", desc: "의존성 버전 고정 없음" },
  { id: "STR001", name: "No README", sev: "LOW", desc: "README.md 파일이 없음" },
];

const SEV_COLORS = { CRITICAL: "#ef4444", HIGH: "#f59e0b", MEDIUM: "#22c55e", LOW: "#3b82f6" };

function useInView(th = 0.1) {
  const r = useRef(null);
  const [v, setV] = useState(false);
  useEffect(() => {
    const el = r.current;
    if (!el) return;
    const o = new IntersectionObserver(([e]) => {
      if (e.isIntersecting) { setV(true); o.disconnect(); }
    }, { threshold: th });
    o.observe(el);
    return () => o.disconnect();
  }, [th]);
  return [r, v];
}

function Reveal({ children, delay = 0 }) {
  const [r, v] = useInView();
  return (
    <div ref={r} style={{
      opacity: v ? 1 : 0,
      transform: v ? "translateY(0)" : "translateY(40px)",
      transition: `all .9s cubic-bezier(.16,1,.3,1) ${delay}s`,
    }}>{children}</div>
  );
}

function FAQItem({ q, a, open, onClick, t }) {
  const ref = useRef(null);
  const [h, setH] = useState(0);
  useEffect(() => { if (ref.current) setH(ref.current.scrollHeight); }, [a]);
  return (
    <div onClick={onClick} style={{ borderBottom: `1px solid ${t.bd}`, cursor: "pointer" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "24px 0", gap: 20 }}>
        <h3 style={{ fontSize: 18, fontWeight: 600, color: t.tx }}>{q}</h3>
        <div style={{ width: 28, height: 28, borderRadius: "50%", border: `1px solid ${t.bd2}`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18, flexShrink: 0, transition: "all .3s", transform: open ? "rotate(45deg)" : "none", color: open ? "#0d9488" : t.tx3 }}>+</div>
      </div>
      <div style={{ maxHeight: open ? h : 0, overflow: "hidden", transition: "max-height .5s cubic-bezier(.16,1,.3,1)" }}>
        <p ref={ref} style={{ fontSize: 16, lineHeight: 1.8, paddingBottom: 28, color: t.tx2 }}>{a}</p>
      </div>
    </div>
  );
}

export default function VibeScanFinal() {
  const [faq, setFaq] = useState(null);
  const [vis, setVis] = useState(false);
  const [dark, setDark] = useState(true);
  const [filter, setFilter] = useState("ALL");

  useEffect(() => { setTimeout(() => setVis(true), 100); }, []);

  const filtered = filter === "ALL" ? RULES : RULES.filter(r => r.sev === filter);

  // Theme tokens
  const t = dark ? {
    bg: "#06060a", bg2: "#0b0b10", bg3: "#0f0f15",
    card: "rgba(255,255,255,.025)", cardHover: "rgba(255,255,255,.05)",
    bd: "rgba(255,255,255,.06)", bd2: "rgba(255,255,255,.1)",
    tx: "#fff", tx2: "rgba(255,255,255,.4)", tx3: "rgba(255,255,255,.2)", tx4: "rgba(255,255,255,.55)",
    navBg: "rgba(6,6,10,.65)", mock: "rgba(0,0,0,.35)", mockBd: "rgba(255,255,255,.05)",
    chip: "rgba(255,255,255,.04)", chipBd: "rgba(255,255,255,.07)", chipTx: "rgba(255,255,255,.35)",
    footTx: "rgba(255,255,255,.15)", footTx2: "rgba(255,255,255,.35)", footTx3: "rgba(255,255,255,.08)",
    gridA: "rgba(6,182,212,.06)", gridB: "rgba(6,182,212,.08)", glow: "rgba(45,212,191,.2)",
    accent: "#2dd4bf", cmd: "#2dd4bf",
    ruleRowBg: "transparent", ruleRowHover: "rgba(255,255,255,.03)",
    pillBg: "rgba(255,255,255,.04)", pillBd: "rgba(255,255,255,.08)", pillTx: "rgba(255,255,255,.4)",
  } : {
    bg: "#f8fafb", bg2: "#f0f4f5", bg3: "#e8eef0",
    card: "#ffffff", cardHover: "#f8fafb",
    bd: "rgba(0,0,0,.06)", bd2: "rgba(0,0,0,.1)",
    tx: "#0f172a", tx2: "rgba(0,0,0,.45)", tx3: "rgba(0,0,0,.2)", tx4: "rgba(0,0,0,.6)",
    navBg: "rgba(248,250,251,.72)", mock: "rgba(0,0,0,.03)", mockBd: "rgba(0,0,0,.06)",
    chip: "rgba(0,0,0,.03)", chipBd: "rgba(0,0,0,.06)", chipTx: "rgba(0,0,0,.4)",
    footTx: "rgba(0,0,0,.15)", footTx2: "rgba(0,0,0,.35)", footTx3: "rgba(0,0,0,.08)",
    gridA: "rgba(6,182,212,.06)", gridB: "rgba(6,182,212,.1)", glow: "rgba(45,212,191,.15)",
    accent: "#0d9488", cmd: "#0d9488",
    ruleRowBg: "transparent", ruleRowHover: "rgba(0,0,0,.02)",
    pillBg: "rgba(0,0,0,.03)", pillBd: "rgba(0,0,0,.08)", pillTx: "rgba(0,0,0,.4)",
  };

  const tr = "transition:all .45s ease;";

  return (
    <div style={{ background: t.bg, color: t.tx2, minHeight: "100vh", fontFamily: "'Outfit','Noto Sans KR',-apple-system,sans-serif", overflowX: "hidden", transition: "background .45s,color .45s" }}>
      <style>{`
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Noto+Sans+KR:wght@400;500;700;900&family=Outfit:wght@400;500;600;700;800;900&display=swap');
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
html{scroll-behavior:smooth}
::selection{background:rgba(45,212,191,.25)}
      `}</style>

      {/* ── NAV ── */}
      <nav style={{ position: "fixed", top: 0, left: 0, right: 0, zIndex: 100, borderBottom: `1px solid ${t.bd}`, transition: "border .45s" }}>
        <div style={{ position: "absolute", top: 0, left: 0, right: 0, bottom: 0, background: t.navBg, backdropFilter: "blur(20px)", transition: "background .45s" }} />
        <div style={{ position: "relative", zIndex: 1, maxWidth: 1200, margin: "0 auto", display: "flex", alignItems: "center", justifyContent: "space-between", height: 64, padding: "0 40px" }}>
          <a href="#home" style={{ textDecoration: "none", fontFamily: "'Outfit',sans-serif", fontWeight: 800, fontSize: 20, color: t.tx, letterSpacing: -.5, transition: "color .45s" }}>VibeScan</a>
          <div style={{ display: "flex", alignItems: "center", gap: 32 }}>
            {["Features", "Rules", "FAQ"].map(s => (
              <a key={s} href={`#${s.toLowerCase()}`} style={{ textDecoration: "none", fontSize: 14, fontWeight: 500, color: t.tx3, transition: "color .2s" }}>{s}</a>
            ))}
            <div onClick={() => setDark(!dark)} style={{ width: 48, height: 26, borderRadius: 13, background: dark ? "#27272a" : "#d4d4d8", display: "flex", alignItems: "center", padding: 3, cursor: "pointer", transition: "background .3s" }}>
              <div style={{ width: 20, height: 20, borderRadius: "50%", background: dark ? "#06b6d4" : "#f59e0b", transform: dark ? "translateX(22px)" : "translateX(0)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 11, transition: "all .3s" }}>{dark ? "\u{1F319}" : "\u{2600}\u{FE0F}"}</div>
            </div>
            <a href="https://github.com/Aguantar/vibescan" target="_blank" rel="noreferrer" style={{ fontSize: 14, fontWeight: 600, textDecoration: "none", padding: "8px 22px", borderRadius: 24, color: t.tx, border: `1px solid ${t.bd2}`, transition: "all .45s" }}>GitHub</a>
          </div>
        </div>
      </nav>

      {/* ── HERO ── */}
      <section id="home" style={{ position: "relative", display: "flex", flexDirection: "column", alignItems: "center", padding: "180px 24px 100px", overflow: "hidden" }}>
        {/* perspective grid */}
        <div style={{ position: "absolute", bottom: 0, left: "50%", transform: "translateX(-50%)", width: "140%", height: 500, transition: "all .45s" }}>
          <div style={{ position: "absolute", bottom: 0, left: 0, right: 0, height: "100%", backgroundImage: `repeating-linear-gradient(90deg,${t.gridA} 0,${t.gridA} 1px,transparent 1px,transparent),repeating-linear-gradient(0deg,${t.gridB} 0,${t.gridB} 1px,transparent 1px,transparent)`, backgroundSize: "80px 60px", transform: "perspective(500px) rotateX(60deg)", transformOrigin: "bottom center", maskImage: "linear-gradient(180deg,transparent 0%,black 30%)", WebkitMaskImage: "linear-gradient(180deg,transparent 0%,black 30%)" }} />
          <div style={{ position: "absolute", bottom: 0, left: "50%", transform: "translateX(-50%)", width: "80%", height: 200, background: `radial-gradient(ellipse at bottom,${t.glow} 0%,transparent 70%)`, filter: "blur(40px)" }} />
        </div>

        <div style={{ opacity: vis ? 1 : 0, transform: vis ? "translateY(0)" : "translateY(20px)", transition: "all .8s cubic-bezier(.16,1,.3,1)", position: "relative", zIndex: 2, textAlign: "center" }}>
          <p style={{ fontSize: 15, color: t.tx3, marginBottom: 28, letterSpacing: .5, transition: "color .45s" }}>바이브코더를 위한 코드 보안 점검 도구</p>
        </div>

        <div style={{ opacity: vis ? 1 : 0, transform: vis ? "translateY(0)" : "translateY(30px)", transition: "all 1s cubic-bezier(.16,1,.3,1) .1s", position: "relative", zIndex: 2, textAlign: "center" }}>
          <h1 style={{ fontFamily: "'Outfit',sans-serif", fontSize: "clamp(48px,7vw,84px)", fontWeight: 800, lineHeight: 1.05, letterSpacing: -3, maxWidth: 800, marginBottom: 24 }}>
            <span style={{ color: dark ? "#2dd4bf" : "#0d9488", transition: "color .45s" }}>Push</span>
            <span style={{ color: t.tx, transition: "color .45s" }}> 전에,</span>
            <br />
            <span style={{ color: t.tx, transition: "color .45s" }}>코드를 </span>
            <span style={{ color: dark ? "#06b6d4" : "#0891b2", transition: "color .45s" }}>점검</span>
            <span style={{ color: t.tx, transition: "color .45s" }}>하세요</span>
          </h1>
        </div>

        <div style={{ opacity: vis ? 1 : 0, transform: vis ? "translateY(0)" : "translateY(30px)", transition: "all 1s cubic-bezier(.16,1,.3,1) .2s", position: "relative", zIndex: 2, display: "flex", flexDirection: "column", alignItems: "center" }}>
          <p style={{ fontSize: 17, color: t.tx2, textAlign: "center", maxWidth: 540, lineHeight: 1.7, marginBottom: 44, transition: "color .45s" }}>민감정보 노출, 보안 취약점, 설정 실수를 로컬에서 분석하여 초보자도 이해할 수 있는 리포트로 제공합니다</p>
          <a href="#features" style={{ display: "inline-block", padding: "14px 36px", border: `1px solid ${t.bd2}`, borderRadius: 28, color: t.tx4, fontSize: 15, fontWeight: 600, textDecoration: "none", fontFamily: "'IBM Plex Mono',monospace", marginBottom: 80, transition: "all .45s" }}>pip install vibescan</a>
        </div>

        {/* Terminal */}
        <div style={{ opacity: vis ? 1 : 0, transform: vis ? "translateY(0) scale(1)" : "translateY(50px) scale(.97)", transition: "all 1.2s cubic-bezier(.16,1,.3,1) .35s", position: "relative", zIndex: 2, maxWidth: 780, width: "100%" }}>
          <div style={{ position: "absolute", top: -40, left: -40, right: -40, bottom: -40, background: `radial-gradient(ellipse,${dark ? "rgba(45,212,191,.08)" : "rgba(45,212,191,.04)"} 0%,transparent 70%)`, filter: "blur(30px)", zIndex: -1 }} />
          <div style={{ background: dark ? "rgba(255,255,255,.03)" : "#fff", border: `1px solid ${t.bd2}`, borderRadius: 16, overflow: "hidden", boxShadow: dark ? "0 40px 80px rgba(0,0,0,.5)" : "0 20px 60px rgba(0,0,0,.06)", transition: "all .45s" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "16px 20px", borderBottom: `1px solid ${t.bd}`, background: dark ? "rgba(255,255,255,.02)" : "rgba(0,0,0,.02)", transition: "all .45s" }}>
              <span style={{ width: 12, height: 12, borderRadius: "50%", background: "#ff5f57" }} />
              <span style={{ width: 12, height: 12, borderRadius: "50%", background: "#febc2e" }} />
              <span style={{ width: 12, height: 12, borderRadius: "50%", background: "#28c840" }} />
              <span style={{ marginLeft: 16, fontFamily: "'IBM Plex Mono',monospace", fontSize: 13, color: t.tx3, transition: "color .45s" }}>vibescan — ~/my-project</span>
            </div>
            <div style={{ padding: "24px 28px", fontFamily: "'IBM Plex Mono',monospace", fontSize: 13, lineHeight: 1.9 }}>
              <div style={{ color: t.cmd }}>$ vibescan scan ./my-project</div>
              <div style={{ color: t.tx3, marginTop: 10, transition: "color .45s" }}>Scanning 147 files...</div>
              <div style={{ marginTop: 14 }}>
                <div style={{ color: "#ef4444" }}>CRITICAL  config.py:23         Hardcoded AWS key (AKIA...)</div>
                <div style={{ color: "#ef4444" }}>CRITICAL  docker-compose.yml:8  POSTGRES_PASSWORD plaintext</div>
                <div style={{ color: "#f59e0b" }}>HIGH      src/api.js:45        API key hardcoded: sk-proj-...</div>
                <div style={{ color: "#f59e0b" }}>HIGH      .env not in .gitignore</div>
                <div style={{ color: dark ? "#eab308" : "#ca8a04" }}>MEDIUM    settings.py:1        DEBUG = True</div>
                <div style={{ color: "#3b82f6" }}>LOW       No README.md found</div>
              </div>
              <div style={{ marginTop: 16, color: t.bd }}>{"━".repeat(48)}</div>
              <div style={{ color: t.tx4, fontWeight: 600, marginTop: 6, transition: "color .45s" }}>  Scanned 147 files | Found 6 issues</div>
              <div style={{ color: t.tx4, fontWeight: 600, transition: "color .45s" }}>  CRITICAL: 2  HIGH: 2  MEDIUM: 1  LOW: 1</div>
              <div style={{ color: t.bd }}>{"━".repeat(48)}</div>
              <div style={{ color: "#22c55e", marginTop: 10 }}>Report saved → vibescan-report.html</div>
            </div>
          </div>
        </div>
      </section>

      {/* ── FEATURES ── */}
      <section id="features" style={{ padding: "140px 24px", maxWidth: 1100, margin: "0 auto" }}>
        <Reveal>
          <div style={{ textAlign: "center", marginBottom: 72 }}>
            <span style={{ fontSize: 14, color: t.tx3, display: "block", marginBottom: 16, transition: "color .45s" }}>Features</span>
            <h2 style={{ fontFamily: "'Outfit',sans-serif", fontSize: "clamp(32px,4vw,48px)", fontWeight: 800, color: t.tx, letterSpacing: -2, transition: "color .45s" }}>
              <span style={{ color: dark ? "#2dd4bf" : "#0d9488" }}>14개 카테고리</span>의<br />보안 점검 엔진
            </h2>
          </div>
        </Reveal>

        {/* Big card */}
        <Reveal delay={0.08}>
          <div style={{ background: t.card, border: `1px solid ${t.bd}`, borderRadius: 20, marginBottom: 20, transition: "all .45s" }}>
            <div style={{ padding: 40, display: "grid", gridTemplateColumns: "1fr 1fr", gap: 36, alignItems: "center" }}>
              <div>
                <h3 style={{ fontFamily: "'Outfit',sans-serif", fontSize: 28, fontWeight: 700, color: t.tx, marginBottom: 16, transition: "color .45s" }}>
                  <span style={{ color: "#ef4444" }}>Secret</span> 탐지
                </h3>
                <p style={{ color: t.tx2, fontSize: 15, lineHeight: 1.7, marginBottom: 20, transition: "color .45s" }}>환경변수, 클라우드 인증, Docker 설정, CI/CD, SSH 키, 프론트엔드 환경변수까지. 바이브코더가 실수하는 모든 경로의 민감정보를 탐지합니다.</p>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                  {[".env 노출", "AWS AKIA", "Firebase", "docker-compose", "terraform", "NEXT_PUBLIC_"].map(label => (
                    <span key={label} style={{ fontSize: 12, padding: "6px 14px", background: t.chip, border: `1px solid ${t.chipBd}`, borderRadius: 8, color: t.chipTx, fontFamily: "'IBM Plex Mono',monospace", transition: "all .45s" }}>{label}</span>
                  ))}
                </div>
              </div>
              <div style={{ background: t.mock, border: `1px solid ${t.mockBd}`, borderRadius: 12, padding: 20, fontFamily: "'IBM Plex Mono',monospace", fontSize: 12, lineHeight: 1.85, transition: "all .45s" }}>
                <div style={{ color: t.cmd }}>$ vibescan scan . --min-severity critical</div>
                <div style={{ height: 10 }} />
                <div style={{ color: "#ef4444" }}>CRITICAL  .env:3</div>
                <div style={{ color: "#ef4444" }}>  Hardcoded OpenAI API key: sk-proj-...</div>
                <div style={{ height: 8 }} />
                <div style={{ color: t.tx3, transition: "color .45s" }}>  Why: API 키가 코드에 직접 입력되어 있습니다.</div>
                <div style={{ color: t.tx3, transition: "color .45s" }}>       Git 커밋 시 누구나 키를 사용할 수 있습니다.</div>
                <div style={{ height: 8 }} />
                <div style={{ color: "#22c55e" }}>  Fix: .env 파일 분리 후 .gitignore 등록</div>
              </div>
            </div>
          </div>
        </Reveal>

        {/* 2-col cards */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginBottom: 20 }}>
          <Reveal delay={0.12}>
            <div style={{ background: t.card, border: `1px solid ${t.bd}`, borderRadius: 20, height: "100%", transition: "all .45s" }}>
              <div style={{ padding: 36 }}>
                <div style={{ background: t.mock, border: `1px solid ${t.mockBd}`, borderRadius: 12, padding: 20, marginBottom: 24, fontFamily: "'IBM Plex Mono',monospace", fontSize: 12, lineHeight: 1.85, transition: "all .45s" }}>
                  <div style={{ color: t.tx3 }}>Python</div>
                  <div style={{ color: "#f59e0b" }}>  eval()              HIGH</div>
                  <div style={{ color: "#f59e0b" }}>  exec()              HIGH</div>
                  <div style={{ color: "#f59e0b" }}>  subprocess(shell)   HIGH</div>
                  <div style={{ height: 6 }} />
                  <div style={{ color: t.tx3 }}>JavaScript</div>
                  <div style={{ color: "#f59e0b" }}>  eval()              HIGH</div>
                  <div style={{ color: "#f59e0b" }}>  innerHTML           HIGH</div>
                </div>
                <h3 style={{ fontFamily: "'Outfit',sans-serif", fontSize: 22, fontWeight: 700, color: t.tx, marginBottom: 12, transition: "color .45s" }}>
                  <span style={{ color: "#f59e0b" }}>위험</span> 코드 패턴
                </h3>
                <p style={{ color: t.tx2, fontSize: 15, lineHeight: 1.7, transition: "color .45s" }}>eval(), SQL 인젝션, XSS, 쉘 인젝션 등 실제 공격에 악용되는 코드 패턴을 검사합니다.</p>
              </div>
            </div>
          </Reveal>
          <Reveal delay={0.16}>
            <div style={{ background: t.card, border: `1px solid ${t.bd}`, borderRadius: 20, height: "100%", transition: "all .45s" }}>
              <div style={{ padding: 36 }}>
                <div style={{ background: t.mock, border: `1px solid ${t.mockBd}`, borderRadius: 12, padding: 20, marginBottom: 24, fontFamily: "'IBM Plex Mono',monospace", fontSize: 12, lineHeight: 1.85, transition: "all .45s" }}>
                  <div style={{ color: t.tx3 }}>Git Hygiene Check</div>
                  <div style={{ height: 6 }} />
                  <div style={{ color: "#ef4444" }}>  x .env        not ignored    CRIT</div>
                  <div style={{ color: "#ef4444" }}>  x *.pem       not ignored    CRIT</div>
                  <div style={{ color: "#22c55e" }}>  v node_modules  ignored      OK</div>
                  <div style={{ color: "#22c55e" }}>  v __pycache__   ignored      OK</div>
                  <div style={{ color: "#22c55e" }}>  v .venv         ignored      OK</div>
                </div>
                <h3 style={{ fontFamily: "'Outfit',sans-serif", fontSize: 22, fontWeight: 700, color: t.tx, marginBottom: 12, transition: "color .45s" }}>
                  <span style={{ color: "#3b82f6" }}>Git</span> Hygiene
                </h3>
                <p style={{ color: t.tx2, fontSize: 15, lineHeight: 1.7, transition: "color .45s" }}>.gitignore 설정을 검사하여 민감 파일이 Git에 커밋되는 것을 방지합니다.</p>
              </div>
            </div>
          </Reveal>
        </div>

        {/* Report card */}
        <Reveal delay={0.2}>
          <div style={{ background: t.card, border: `1px solid ${t.bd}`, borderRadius: 20, transition: "all .45s" }}>
            <div style={{ padding: 40, display: "grid", gridTemplateColumns: "1fr 1fr", gap: 36, alignItems: "center" }}>
              <div style={{ background: t.mock, border: `1px solid ${t.mockBd}`, borderRadius: 12, padding: 20, fontFamily: "'IBM Plex Mono',monospace", fontSize: 12, transition: "all .45s" }}>
                <div style={{ color: t.tx4, fontWeight: 600, marginBottom: 14, transition: "color .45s" }}>vibescan-report.html</div>
                <div style={{ display: "flex", gap: 10, marginBottom: 16 }}>
                  {[["CRITICAL", "2", "#ef4444"], ["HIGH", "2", "#f59e0b"], ["MEDIUM", "1", "#22c55e"], ["LOW", "1", "#3b82f6"]].map(([l, n, c]) => (
                    <div key={l} style={{ flex: 1, background: c + "0c", border: "1px solid " + c + "20", borderRadius: 10, padding: "12px 8px", textAlign: "center" }}>
                      <div style={{ fontSize: 24, fontWeight: 800, color: c, fontFamily: "'Outfit',sans-serif" }}>{n}</div>
                      <div style={{ fontSize: 10, color: c, fontFamily: "'IBM Plex Mono',monospace", fontWeight: 600, marginTop: 4 }}>{l}</div>
                    </div>
                  ))}
                </div>
                <div style={{ height: 6, borderRadius: 3, background: t.chip, overflow: "hidden", display: "flex" }}>
                  <div style={{ width: "33%", background: "#ef4444" }} />
                  <div style={{ width: "33%", background: "#f59e0b" }} />
                  <div style={{ width: "17%", background: "#22c55e" }} />
                  <div style={{ width: "17%", background: "#3b82f6" }} />
                </div>
              </div>
              <div>
                <h3 style={{ fontFamily: "'Outfit',sans-serif", fontSize: 28, fontWeight: 700, color: t.tx, marginBottom: 16, transition: "color .45s" }}>
                  <span style={{ color: dark ? "#a78bfa" : "#7c3aed" }}>설명형</span> 리포트
                </h3>
                <p style={{ color: t.tx2, fontSize: 15, lineHeight: 1.7, transition: "color .45s" }}>콘솔, JSON, HTML 세 가지 형식을 지원합니다. 각 문제에 대해 왜 위험한지, 어떻게 고쳐야 하는지까지 안내합니다.</p>
              </div>
            </div>
          </div>
        </Reveal>
      </section>

      {/* ── RULES (from v2) ── */}
      <section id="rules" style={{ padding: "140px 24px" }}>
        <div style={{ maxWidth: 960, margin: "0 auto" }}>
          <Reveal>
            <div style={{ textAlign: "center", marginBottom: 36 }}>
              <span style={{ fontSize: 14, fontWeight: 600, color: dark ? "rgba(45,212,191,.5)" : "rgba(13,148,136,.6)", letterSpacing: 2, textTransform: "uppercase", fontFamily: "'IBM Plex Mono',monospace", transition: "color .45s" }}>RULES</span>
              <h2 style={{ fontFamily: "'Outfit',sans-serif", fontSize: "clamp(32px,4vw,48px)", fontWeight: 800, color: t.tx, letterSpacing: -2, marginTop: 12, transition: "color .45s" }}>탐지 규칙 목록</h2>
              <p style={{ color: t.tx2, marginTop: 10, fontSize: 16, transition: "color .45s" }}>VibeScan이 검사하는 {RULES.length}개의 규칙</p>
            </div>
          </Reveal>

          <Reveal delay={0.06}>
            <div style={{ display: "flex", gap: 10, justifyContent: "center", marginBottom: 36, flexWrap: "wrap" }}>
              {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map(s => {
                const on = filter === s;
                const c = s === "ALL" ? t.accent : SEV_COLORS[s];
                const cnt = s === "ALL" ? RULES.length : RULES.filter(r => r.sev === s).length;
                return (
                  <button key={s} onClick={() => setFilter(s)} style={{
                    padding: "10px 22px", borderRadius: 24, border: "none", cursor: "pointer",
                    background: on ? (c + "18") : t.pillBg,
                    color: on ? c : t.pillTx,
                    fontSize: 13, fontWeight: 700, fontFamily: "'IBM Plex Mono',monospace",
                    outline: `1px solid ${on ? c + "35" : t.pillBd}`,
                    transition: "all .25s"
                  }}>
                    {s} ({cnt})
                  </button>
                );
              })}
            </div>
          </Reveal>

          <Reveal delay={0.1}>
            <div style={{ background: t.card, border: `1px solid ${t.bd}`, borderRadius: 20, overflow: "hidden", transition: "all .45s" }}>
              {/* Header */}
              <div style={{ display: "grid", gridTemplateColumns: "80px 1fr 100px", padding: "14px 32px", borderBottom: `1px solid ${t.bd}`, fontSize: 12, color: t.tx3, fontWeight: 700, letterSpacing: 1.5, fontFamily: "'IBM Plex Mono',monospace", transition: "all .45s" }}>
                <span>ID</span>
                <span>설 명</span>
                <span style={{ textAlign: "right" }}>심 각 도</span>
              </div>
              {/* Rows */}
              {filtered.map((r, i) => {
                const c = SEV_COLORS[r.sev];
                return (
                  <div key={r.id} style={{
                    display: "grid", gridTemplateColumns: "80px 1fr 100px",
                    padding: "18px 32px",
                    borderBottom: i < filtered.length - 1 ? `1px solid ${t.bd}` : "none",
                    alignItems: "center", transition: "all .15s"
                  }}>
                    <code style={{ fontFamily: "'IBM Plex Mono',monospace", color: t.accent, fontSize: 13, fontWeight: 600 }}>{r.id}</code>
                    <div>
                      <span style={{ fontWeight: 700, color: t.tx, marginRight: 8, transition: "color .45s" }}>{r.name}</span>
                      <span style={{ color: t.tx2, transition: "color .45s" }}>— {r.desc}</span>
                    </div>
                    <div style={{ textAlign: "right" }}>
                      <span style={{
                        display: "inline-block", padding: "4px 14px", borderRadius: 8,
                        background: c + (dark ? "15" : "10"),
                        color: c, fontSize: 11, fontWeight: 700,
                        fontFamily: "'IBM Plex Mono',monospace",
                        border: `1px solid ${c}25`
                      }}>{r.sev}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </Reveal>
        </div>
      </section>

      {/* ── FAQ ── */}
      <section id="faq" style={{ padding: "140px 24px", maxWidth: 720, margin: "0 auto" }}>
        <Reveal>
          <span style={{ fontSize: 14, fontWeight: 600, color: dark ? "rgba(45,212,191,.5)" : "rgba(13,148,136,.6)", letterSpacing: 1, textTransform: "uppercase", display: "block", marginBottom: 20, fontFamily: "'IBM Plex Mono',monospace", transition: "color .45s" }}>FAQ</span>
          <h2 style={{ fontFamily: "'Outfit',sans-serif", fontSize: "clamp(30px,4vw,44px)", fontWeight: 800, color: t.tx, letterSpacing: -1.5, marginBottom: 12, transition: "color .45s" }}>자주 묻는 질문</h2>
          <p style={{ color: t.tx3, fontSize: 15, marginBottom: 56, transition: "color .45s" }}>더 궁금한 점이 있으신가요? <a href="https://github.com/Aguantar/vibescan/issues" target="_blank" rel="noreferrer" style={{ color: dark ? "rgba(45,212,191,.6)" : "rgba(13,148,136,.7)", textDecoration: "none" }}>GitHub에서 문의하세요.</a></p>
        </Reveal>
        <Reveal delay={0.08}>
          <div>
            {FAQS.map((f, i) => (
              <FAQItem key={i} q={f.q} a={f.a} open={faq === i} onClick={() => setFaq(faq === i ? null : i)} t={t} />
            ))}
          </div>
        </Reveal>
      </section>

      {/* ── CTA ── */}
      <section style={{ position: "relative", padding: "160px 24px", textAlign: "center", overflow: "hidden" }}>
        <div style={{ position: "absolute", bottom: 0, left: "50%", transform: "translateX(-50%)", width: "100%", height: 400, background: `radial-gradient(ellipse 50% 70% at 50% 100%,${dark ? "rgba(45,212,191,.08)" : "rgba(45,212,191,.06)"} 0%,transparent 60%)`, pointerEvents: "none" }} />
        <Reveal>
          <h2 style={{ fontFamily: "'Outfit',sans-serif", fontSize: "clamp(32px,5vw,52px)", fontWeight: 800, color: t.tx, letterSpacing: -2, marginBottom: 16, transition: "color .45s" }}>
            코드를 세상에 <span style={{ color: dark ? "#2dd4bf" : "#0d9488" }}>내보내기 전에.</span>
          </h2>
          <p style={{ fontSize: 17, color: t.tx2, marginBottom: 44, lineHeight: 1.7, transition: "color .45s" }}>한 줄의 명령으로 프로젝트를 안전하게 점검하세요</p>
          <a href="https://github.com/Aguantar/vibescan" target="_blank" rel="noreferrer" style={{ display: "inline-block", padding: "16px 40px", background: "linear-gradient(135deg,#2dd4bf,#06b6d4)", color: dark ? "#06060a" : "#fff", fontSize: 16, fontWeight: 700, textDecoration: "none", borderRadius: 28, boxShadow: "0 4px 24px rgba(45,212,191,.25)" }}>시작하기</a>
          <p style={{ color: t.tx3, fontSize: 13, marginTop: 20, transition: "color .45s" }}>오픈소스 · 무료 · 로컬 전용</p>
        </Reveal>
      </section>

      {/* ── FOOTER ── */}
      <footer style={{ borderTop: `1px solid ${t.bd}`, padding: "64px 24px 40px", transition: "border .45s" }}>
        <div style={{ maxWidth: 1200, margin: "0 auto" }}>
          <div style={{ display: "grid", gridTemplateColumns: "2.5fr 1fr 1fr 1fr", gap: 48, marginBottom: 56 }}>
            <div>
              <span style={{ fontFamily: "'Outfit',sans-serif", fontWeight: 800, fontSize: 18, color: t.tx, display: "block", marginBottom: 16, transition: "color .45s" }}>VibeScan</span>
              <p style={{ color: t.footTx, fontSize: 14, lineHeight: 1.7, maxWidth: 280, transition: "color .45s" }}>Your code never leaves your machine. VibeScan runs entirely locally.</p>
            </div>
            {[
              ["Product", [["Features", "#features"], ["Rules", "#rules"], ["FAQ", "#faq"]]],
              ["Resources", [["GitHub", "https://github.com/Aguantar/vibescan"], ["PyPI", "https://pypi.org"], ["Blog", "https://calme.tistory.com"]]],
              ["Legal", [["MIT License", null]]],
            ].map(([title, links]) => (
              <div key={title}>
                <div style={{ color: t.tx3, fontSize: 12, fontWeight: 700, textTransform: "uppercase", letterSpacing: 1.5, marginBottom: 20, transition: "color .45s" }}>{title}</div>
                {links.map(([label, href]) => href ? (
                  <a key={label} href={href} style={{ display: "block", color: t.footTx2, fontSize: 14, textDecoration: "none", marginBottom: 12, transition: "color .45s" }}>{label}</a>
                ) : (
                  <span key={label} style={{ display: "block", color: t.footTx2, fontSize: 14, marginBottom: 12, transition: "color .45s" }}>{label}</span>
                ))}
              </div>
            ))}
          </div>
          <div style={{ borderTop: `1px solid ${t.bd}`, paddingTop: 24, display: "flex", justifyContent: "space-between", transition: "border .45s" }}>
            <span style={{ color: t.footTx3, fontSize: 13, transition: "color .45s" }}>© 2026 VibeScan. All rights reserved.</span>
            <span style={{ color: t.footTx3, fontSize: 13, transition: "color .45s" }}>Built for vibe coders</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
