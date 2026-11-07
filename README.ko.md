# Advisory Triage for Network Operators

English: [README.md](README.md)

**권고 링크 목록**과 **장비 인벤토리(CSV 업로드)**를 주면, 권고를
직접 가져와 권고마다 **근거를 숨기지 않고 제시하는 단 하나의 방어
가능한 판정** — **AFFECTED(해당 있음)**, **NOT AFFECTED(해당
없음)**, **CANNOT DETERMINE(판정 불가)** — 을 돌려줍니다. (권고
하나를 직접 붙여넣는 방식도 두 번째 입력 모드로 계속 제공됩니다.)

이 도구는 **Clocked Build Challenge**를 위해 네트워크 운영자가,
네트워크 운영자를 위해 만들었습니다. 커버리지는 네트워크 장비에만
한정되지 않고 플릿 전체를 대상으로 합니다. 업로드한 인벤토리에
있는 것은 무엇이든 범위 안에 들어갑니다 — 네트워크 장비, 보안
장비(방화벽 / IPS / WAF / DDoS), 로드 밸런서와 ADC, 그리고
서버까지. 정직한 세 번째 판정이 이 도구의 핵심입니다. 권고가
영향받는 버전을 명시하지 않으면, "해당 없음"이라고 추측하는 대신
그렇다고 말합니다.

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/papilion/clocked-advisory-triage)

## 언어

UI는 상단의 언어 토글로 **영어와 한국어**를 지원하며, 기본값은
영어입니다. 판정, 장비별 사유, 경고, 체크리스트가 모두
현지화됩니다. 번들로 제공되는 샘플 권고는 영어 문서 그대로
유지되고, Clocked Verify로 보내는 판정 주장(claim)은 영어로
유지됩니다.

## 데모

- 라이브 데모: TBD (배포 후 링크 추가 예정)
- 데모 영상: TBD (링크 추가 예정)
- 키가 없어도 앱은 번들로 제공되는 7개의 합성 샘플로 **모의
  모드(Mock Mode)** 로 실행됩니다 — 아래를 참고하세요. 가입 없이도
  데모 경로를 사용해 볼 수 있습니다.

## 로컬 실행 (3분 이내)

```bash
git clone <this-repo>
cd clocked-advisory-triage
python3 -m venv .venv
. .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

앱은 **배치 모드**로 열립니다. **Sample advisories (GitHub)**
프리셋을 클릭한 뒤 **Run Batch**를 누르면, 앱이 GitHub 목록에서
7개의 샘플 권고 링크를 직접 수집해 전부 판정합니다. API 키 없이도
동작합니다(Mock Mode, canned Clocked 응답 사용). 또는
**Paste (single advisory)** 모드로 전환해 샘플 버튼(**Sample
1–7**) 중 하나를 클릭하고 **Run Triage**를 누르세요.

본인의 권고를 실시간으로 분석하려면 Clocked API 키를 설정하세요
(무료 계정: 4,000 크레딧; 챌린지 코드 `CLOCKEDHACKATHON`으로
16,000 크레딧 추가):

```bash
export CLOCKED_API_KEY=your-clocked-api-key-here   # placeholder - use your own key
streamlit run app.py
```

또는 `.streamlit/secrets.toml`(git-ignore 대상)에
`CLOCKED_API_KEY`를 넣으세요. 실제 키는 절대 커밋하지 마세요.

## GitHub Codespaces에서 실행 (실시간)

로컬 설치가 전혀 필요 없습니다 — 이 README 상단의 **Open in
GitHub Codespaces** 배지를 클릭하세요:

1. `main`에 Codespace를 만드세요. dev container
   (`.devcontainer/devcontainer.json`)가 `requirements.txt`를
   설치하고 앱을 자동으로 시작합니다.
2. 포트 **8501**이 포워딩되며 "Advisory Triage (Streamlit)"라는
   라벨이 붙고, 실행 중인 앱의 미리보기가 자동으로 열립니다.
   (열리지 않으면 **Ports** 탭을 열어 8501 포트의 지구본 아이콘을
   클릭하세요.)
3. 키가 없으면 앱은 **데모(모의) 모드**로 열립니다 — 번들 샘플
   7개가 끝까지 동작합니다.
4. **LIVE 모드**를 쓰려면 `CLOCKED_API_KEY`라는 이름의
   Codespaces secret을 추가하세요: 저장소 **Settings → Secrets
   and variables → Codespaces → New repository secret**.
   Codespaces는 secret을 환경 변수로 노출하고, 앱은 환경에서
   `CLOCKED_API_KEY`를 가장 먼저 읽기 때문에, Codespace를 만들기
   *전에* secret을 만들거나, 만든 뒤에는 Codespace를 다시
   빌드해야 반영됩니다. 실행 중인 Codespace 안에서는 터미널에서
   `export CLOCKED_API_KEY=...` 후 앱을 재시작하거나, 로컬 `.env`
   파일(git-ignore 대상, **절대 커밋 금지**)에 키를 넣어 셸에
   로드한 뒤 재시작해도 됩니다:
   `set -a; . ./.env; set +a`.

키는 이 저장소에 절대 저장되지 않습니다.

한국어 사용자도 같은 순서입니다: 위 배지를 눌러 Codespace를 만들면
앱이 자동으로 실행되고, 키가 없으면 데모 모드로 열립니다.

## 배치 모드 — 기본 워크플로

기본 화면은 복사-붙여넣기가 아니라 실제 판정 대상 더미를 위해
설계됐습니다:

1. **권고 소스** — 네 가지 유입 경로:
   - **목록 페이지 (자동 수집)** — 벤더 목록/게시판 URL 하나를
     주면(프리셋 버튼: Cisco PSIRT, Arista, Juniper, 번들 GitHub
     샘플) 앱이 권고 링크를 직접 수집합니다: href나 텍스트가
     권고처럼 보이는 동일 도메인 앵커(`advisory`, `cisco-sa`,
     `JSA…`, `/advisories/` 등)를 중복 제거해 최대 **15**개까지.
     GitHub tree 페이지는 raw 파일 URL로 변환됩니다. 소스를
     수집할 수 없을 때 — 봇 챌린지 페이지이거나 HTML에 링크가
     없는 JavaScript 셸이면 — 앱은 그 사실을 솔직히 알리고 링크
     목록 모드를 안내합니다. 결과를 가장하지 않습니다.
   - **링크 목록** — 권고 URL을 한 줄에 하나씩 붙여넣습니다
     (폴백/고급 옵션). 앱이 각 페이지를 직접 가져오고(HTML은 읽을
     수 있는 텍스트로 축소, 평문 권고는 그대로 통과) 링크마다 전체
     파이프라인을 실행합니다. 잘못된 링크 하나가 배치 전체를
     중단시키지 않습니다 — 사유와 함께 `FETCH FAILED` 행으로
     표시됩니다.
   - **취약점 피드 (NVD / KEV)** — 포털을 완전히 건너뛰고 공식
     기계 판독 피드를 대신 질의합니다: **NVD CVE API**(최대 4개의
     키워드 질의, 인벤토리의 장비 수 기준으로 벤더 우선순위 결정
     — 알려진 네트워크 벤더는 "Cisco IOS XE", "Juniper Junos",
     "Arista EOS"처럼 선별된 제품 키워드를 사용하고, F5부터
     Microsoft까지 그 외 플릿 벤더는 "<Vendor> <top product
     token>" 질의를 도출합니다 — API 키 불필요)와 CISA의 **Known
     Exploited Vulnerabilities** 카탈로그(로컬에서 벤더와 모델
     계열로 필터링). 이유: 실측해 보면 벤더 포털은 자동 수집을
     차단합니다(Arista는 봇 챌린지를 띄우고, Cisco/Juniper 목록은
     JavaScript 셸입니다). 반면 NVD와 KEV는 애초에 기계가 읽도록
     공개된 채널입니다. 각 CVE는 권고 텍스트가 됩니다(NVD
     설명에는 영향 버전 서술이 담기고, NVD CPE 구성 범위는
     구조화된 "affected ranges" 섹션으로 덧붙으며, KEV의 조치
     기한은 Action 블록의 마감일로 흘러 들어갑니다) 그리고 같은
     파이프라인으로 판정됩니다. 실행 후에는 피드별 건수와 솔직한
     빈/실패 상태가 표시됩니다. Mock Mode에서는 이 소스가 네트워크
     대신 번들 fixture 파일(실제 공개 CVE/KEV 데이터를 다듬은
     것)을 읽으므로 데모가 오프라인으로 동작합니다.
   - **제조사 원문 (전체 텍스트 추적)** — 발견은 첫 단계일
     뿐입니다. 판정에 앞서 앱은 수집된 각 CVE를 제조사의 원문
     전체 텍스트까지 따라갑니다(실행당 최대 10건, 실제 악용 중인
     KEV 항목 우선) 그리고 *그것*을 판정하며, 피드 요약은 참고용으로
     아래에 덧붙여 유지합니다. 경로: **Cisco** — 권고의 공개
     CSAF 2.0 JSON(product tree에서 조합한 영향 제품명/버전, 수정
     버전 목록, 완화 텍스트); **Juniper** — JSA 문서 페이지 자체,
     가져온 내용이 실제 문서 텍스트일 때만 채택(≥ 400자 — 포털은
     종종 JavaScript 셸로 응답합니다); **Arista** — 도출된 CSAF
     JSON URL; 그리고 **모든** 벤더에 대한 폴백으로, CVEProject
     cvelistV5 미러에서 가져오는 벤더 제출 **CVE 레코드(CNA)** —
     벤더가 직접 제출한 구조화 영향 제품, 플랫폼, 버전 경계
     (`version < lessThan`). CNA 경로는 벤더 범용이라 네트워크
     3사뿐 아니라 플릿 인벤토리 속 보안·로드밸런서·서버 벤더까지
     커버합니다. UI는 원문이 추적된 권고 수를 표시하고, 각 결과는
     링크와 함께 제조사 출처를 명시합니다. 모든 경로가 실패하면
     항목은 피드 텍스트를 유지하고 제조사 출처는 붙지 않습니다 —
     추적은 다른 권고의 내용을 빌려오지 않고, 없는 내용을
     지어내지 않습니다.
   - **권고 파일 업로드** — 포털이 앱은 막지만 본인은 막지 않을
     때, 본인 브라우저에서 권고 페이지를 저장해 업로드하세요
     (`.txt`, `.html`, `.htm`, `.md`, 최대 10개 파일): 수집은
     브라우저가, 판정은 앱이 합니다. 파일은 인벤토리 CSV와 같은
     방식(UTF-8 → CP949)으로 디코딩되고 HTML은 가져온 페이지와
     똑같이 텍스트로 축소됩니다.
2. **관련성 프리필터** — 어떤 Clocked 호출보다 먼저, 가져온 각
   권고는 인벤토리의 제품 공간(CSV에서 뽑은 모델 코어와 단어,
   플릿 벤더, 일반 네트워크 장비 용어)에 대해 로컬로
   스크리닝됩니다. 어느 것도 언급하지 않는 권고는
   `SKIPPED — not related to the uploaded inventory`로 표시되고
   **API 호출이 0회**입니다. 토글("Judge all advisories")로 필터를
   끌 수 있습니다.
3. **인벤토리 CSV** — 전체 장비 인벤토리를 한 번 업로드하면 모든
   권고가 모든 장비에 대해 판정됩니다. 열 처리는 유연합니다:
   - 헤더는 대소문자를 가리지 않고 영어 또는 한국어로
     매칭됩니다: hostname ← `host|hostname|name|device|장비명|호스트명`,
     model ← `model|모델|장비모델`,
     version ← `version|os|os version|버전|펌웨어`,
     여기에 선택 열인 `vendor|벤더|제조사`가 있어, 모델 앞에
     벤더가 이미 붙어 있지 않으면 접두사로 붙습니다;
   - 추가 열(serial, IP, region 등)은 무시됩니다;
   - 인식 가능한 헤더 행이 없으면 열은 위치 기준으로 host, model,
     version으로 간주합니다;
   - 인코딩은 UTF-8(BOM 허용)으로 디코딩하고 한국 Excel
     내보내기를 위해 CP949 폴백을 두며, 구분자는 `,`, `;`, 탭 중
     무엇이든 됩니다;
   - host, model, version 중 하나라도 빠진 행은 건너뛰고 그 수를
     세며, 실행 전에 파싱된 첫 장비들이 미리보기로 표시됩니다.
4. **결과** — 먼저 **조치 요약(Action summary)**(조치가 필요한
   권고만, AFFECTED를 CANNOT DETERMINE 앞에, 각각 링크와 함께 한
   줄씩), 이어서 요약 표(권고별 판정, 긴급도, 영향 장비 수, 조건
   플래그; 건너뛴 항목과 가져오기 실패 항목도 각각의 행으로
   표시), 그리고 권고마다 펼칠 수 있는 상세가 하나씩. 모든 상세
   — 배치와 단일 모드 모두 — 에는 결정적인 **Action required**
   블록이 들어갑니다: AFFECTED이면 영향받는 호스트명, 업그레이드할
   수정 버전, 마감일, 권고가 명시한 우회 조치(적용 조건과 같은
   집중 Extract 패스로 추출); CANNOT DETERMINE이면 확인할 정확한
   조건; NOT AFFECTED이면 "No action required."

배치가 폭주하지 않도록 하는 상한: 링크 목록 실행당 최대 **10개**
링크(초과분은 건너뜀으로 보고), 목록당 수집 링크 **15**개,
다운로드당 **2 MB**, 권고당 추출 텍스트 **40,000자**, 가져오기
타임아웃 15초. CSV를 업로드하지 않으면 번들 샘플 인벤토리를
사용하므로 데모가 한 번의 클릭으로 실행됩니다. 상단의 모드
전환에서 **Paste (single advisory)** 모드 — 원래의 텍스트
붙여넣기 UI — 도 계속 사용할 수 있습니다.

### 1년치 피드 히스토리, 로컬 스크리닝

피드 소스는 1년치 CVE를 하나하나 판정하지 않습니다 — 대부분은
어떤 모델 호출보다 먼저 벤더 자신의 구조화 데이터로 결론이
납니다:

1. **수집 (365일).** NVD는 인벤토리 벤더별로 최대 **119일**
   단위의 연속 발행일 구간으로 질의하고(API는 한 구간을 120일로
   제한합니다), 각 구간 안에서는 페이지당 500건씩 페이지네이션해
   `totalResults`가 소진될 때까지 가져옵니다 — 벤더별 하드 캡은
   고유 CVE 1,000건이며, 도달하면 잘림(truncation)으로
   보고됩니다. KEV 카탈로그는 전체를 매칭합니다(캡 300, 최신순).
   항목은 구간과 피드를 가로질러 CVE id로 중복 제거하되 — NVD
   `configurations`를 가진 레코드를 우선합니다 — KEV 항목은 같은
   CVE의 NVD 항목으로 병합되어(악용 확인 플래그, 조치 기한) 어떤
   피드가 지목하든 하나의 CVE는 하나의 항목이 됩니다.
2. **로컬 스크리닝 (API 호출 0회).** 각 항목의 구조화 CPE 범위를
   인벤토리의 모든 장비 버전에 대해 로컬로 평가하며, 결정적
   매처와 같은 버전 비교를 재사용합니다: 영향 범위 **안**의
   버전은 후보 적중(candidate-hit); 그 제품의 **모든 범위 밖**의
   버전은 해당 장비를 클리어합니다; 범위가 없거나 비교를 확정할
   수 없으면(예: `17.9.4` 대 경계 `17.9.4a` 같은 접미사 문자
   동점) **불확실**로 남습니다. 관련 장비가 *전부* 클리어된
   항목은 로컬 **NOT AFFECTED** 행이 되고(근거: "local-screen");
   인벤토리 제품과 무관한 항목은 스크리닝에서 제외되어 건수만
   셉니다; 적중이 있거나 관련 장비가 불확실한 모든 항목은 후보가
   됩니다.
3. **정밀 판정 (예산제).** 후보는 제조사 원문까지 추적된 뒤,
   우선순위 순서 — **KEV 먼저, 그다음 CVSS 심각도, 그다음
   최신순** — 로 전체 Clocked 파이프라인으로 판정되며, 실행당
   최대 **30건**입니다("Judge all" 토글은 예산을 200으로
   올립니다). 예산을 넘는 후보는 조용히 버려지지 않습니다:
   스크리닝이 결론을 내지 못했고 이번 실행의 정밀 판정 예산을
   넘었다고 명시하는 로컬 **CANNOT DETERMINE** 행으로 표시됩니다.

결과 위의 캡션은 단계마다 보고합니다("Collected last 365 days:
NVD *n* · KEV *k*", "Local screening: *a* not affected by version
range · *b* not in fleet · *c* deep-triaged"). 로컬 판정은 모델이
아니라 벤더가 공개한 구조화 범위에서 도출되며, Clocked 호출을
전혀 쓰지 않습니다.

## 동작 방식

```
Advisory text ──► Clocked Extract ──► structured fields
                                          │
Inventory ──────► Local deterministic ◄───┘
                  matcher (0 API calls)     per-device verdicts
                                          │
                  Clocked Decide ─────────► urgency + evidence sufficiency
                                          │
                  Clocked Verify ─────────► verdict claim checked
                  (grounding)               against advisory + inventory
                                          │
                                    Final verdict + checklist
```

1. **Extract** — Clocked `extract`가 벤더, 제품, 영향 버전,
   권고/CVE id, 심각도, 수정 버전, 조치 기한, 그리고 **적용
   조건**("TerminAttr가 CloudVision과 통신할 때만" 같은 문장)을
   원문 그대로 뽑아냅니다. 조건은 필드가
   `applicability_conditions` 하나뿐인 **두 번째 집중 Extract
   호출**로 가져옵니다: 실제 API로 측정해 보면, 요청 필드 수가
   많을수록 span 추출 신뢰도가 떨어집니다 — 전체 필드 호출에서는
   조건 문장이 텍스트에 분명히 있는데도 조건이 비어 돌아왔지만,
   단일 필드에 집중한 호출은 안정적으로 반환했습니다. **버전
   제약**은 앱이 복사하지 않고 계산하는 유일한 항목입니다:
   Extract는 span 기반이라 정규화된 토큰은 span이 아니어서 절대
   내보내지 않습니다(스키마도 더 이상 요구하지 않습니다) — 그래서
   앱은 원문 서술에서 로컬로 결정적으로 제약을 도출합니다
   ("versions prior to 21.4R2" 같은 서술은 `before:21.4R2`가
   됩니다; `up_to:X`, `train_before:T:B`도 마찬가지), 명시된 수정
   버전을 보호된 폴백으로 둡니다. 그 외의 것은 추론하지 않습니다.
2. **Match (로컬, 결정적, API 호출 0회)** — 각 인벤토리 줄을
   추출된 제품 및 버전과 비교합니다. 정확 일치, 와일드카드
   (`17.9.x`), 범위(`17.9.1-17.9.5`) 버전 매칭. 라이브로 반환되는
   영향 버전 항목은 벤더 접두사를 달고 있을 수 있는데("EOS
   4.30.5M", "Junos OS 21.2R1"), 그런 항목은 버전 토큰으로
   판정하고, 서술형 표현은 절대 토큰으로 축소하지 않습니다. 명시적
   버전 목록으로 장비가 결정되지 않으면 정규화된 제약을 수치로
   평가합니다; 수치 비교가 진짜로 결정 불가능하면(예: EOS
   `4.30.5F` 대 `4.30.5M` — 접미사 순서는 벤더마다 다릅니다)
   결과는 추측이 아닌 **CANNOT DETERMINE**입니다. 버전을 파싱할
   수 없는 후보 장비, 또는 영향 버전이 명시되지 않은 제품 일치도
   마찬가지로 **CANNOT DETERMINE**입니다 — 조용히 "해당 없음"이
   되지 않습니다. 그리고 권고에 적용 조건이 있으면, 제품+버전
   일치는 CANNOT DETERMINE으로 **게이트**됩니다: 인벤토리에는
   조건에 대한 정보가 없으므로, UI는 "Applicability conditions
   to verify" 아래에 조건을 명시하고, 조건 확인 경고를 추가하며,
   구체적인 확인 절차를 체크리스트 맨 위에 둡니다.
3. **Decide** — Clocked `decide`가 확률과 함께 세 가지 질문에
   답합니다: 조치가 즉각적인가, 계획으로 세워야 하는가, 그리고
   권고의 근거가 판정 자체를 내릴 만큼 충분한가? 충분성이 낮으면
   전체 판정이 CANNOT DETERMINE으로 강등됩니다.
4. **Verify** — Clocked `grounding`이 한 문장짜리 판정 주장을
   **두 원문 모두**와 대조합니다: **권고와, 매칭에 사용된
   인벤토리**. 주장은 인벤토리에 관한 사실도 단언하므로(예: 어떤
   장비가 인벤토리에 있다는 것), 권고만으로 대조하면 올바른
   판정을 잘못 기각하게 됩니다. 검증되지 않으면 판정은 CANNOT
   DETERMINE으로 뒤집히고 경고가 눈에 띄게 표시됩니다.

합계: **실행당 정확히 4회의 Clocked 호출.**

### 사용 엔드포인트

| 단계 | Clocked endpoint | SDK call | 용도 |
|------|------------------|----------|------|
| 1 | Extract | `client.extract` | 권고에서 구조화 필드 추출 |
| 1b | Extract (focused) | `client.extract` | 적용 조건만 — 단일 필드 호출. 해당 필드의 span 추출이 전체 필드 세트 안에서는 신뢰할 수 없음이 확인됐기 때문 |
| 3 | Decide | `client.decide` | 긴급도 + 근거 충분성, 확률 포함 |
| 4 | Verify | `client.grounding` | 판정 주장을 권고 + 인벤토리와 대조 |

> **참고:** "Verify"는 SDK의 **grounding** 엔드포인트를 가리키는
> 챌린지 측 명칭입니다. 코드와 SDK에서는 `grounding`이고, 챌린지
> 카테고리에서는 Verify / Compare / Rerank로 묶입니다.

목표 수상 카테고리: **Best Overall App**, **Best Use of Decide,
Extract, or Fill**(1 + 3단계), **Best Use of Verify, Compare, or
Rerank**(4단계).

## 샘플 가이드

모든 샘플은 **합성 데이터이며 공개해도 안전**합니다: 지어낸 권고
ID, 지어낸 호스트명, 실제 IP 없음, 실제 벤더 텍스트 없음.

| 샘플 | 권고 | 예상 전체 판정 |
|--------|----------|--------------------------|
| Sample 1 | Cisco 스타일: Catalyst 9300, IOS XE 17.9.x 영향, High, 수정 버전 + 마감일 | **AFFECTED** (CORE-SW-01이 17.9.4 실행 중) |
| Sample 2 | Juniper 스타일: MX 시리즈만, 인벤토리에 없는 버전 범위 | **NOT AFFECTED** |
| Sample 3 | KISA 스타일: 제품 계열만 명시, **버전 없음, 수정 버전 없음** | **CANNOT DETERMINE** |
| Sample 4 | Arista 스타일: Arista 7050SX3, EOS 4.30.4M/4.30.5M 영향, High, 수정 버전 + 마감일 | **AFFECTED** (DC-SW-01이 4.30.5M 실행 중; DC-SW-02는 7050CX3 — 다른 제품이라 해당 없음) |
| Sample 5 | Juniper 스타일: QFX5110, Junos OS 21.2R1–21.2R3 영향, High, 수정 버전 + 마감일 | **AFFECTED** (AGG-RTR-01이 21.2R3 실행 중) |
| Sample 6 | Juniper 스타일: MX480, 영향 버전이 서술로만 명시 — "Junos OS versions **prior to 21.4R2**", 수정 21.4R2, High | **AFFECTED** (CORE-RTR-01이 21.3R3 실행 중, 로컬로 도출한 `before:21.4R2` 제약으로 판정) |
| Sample 7 | Arista 스타일: Arista 7050SX3, EOS 4.30.5M 영향, 단 **TerminAttr가 CloudVision(CVP)과 통신하도록 구성됐을 때만** | **CANNOT DETERMINE** (DC-SW-01은 제품 + 버전이 일치하지만, 인벤토리로는 TerminAttr 조건을 확인할 수 없음) |

세 벤더 — Cisco, Juniper, Arista — 모두 **AFFECTED** 데모
케이스가 있습니다(샘플 1, 5, 4). 샘플 2와 5는 둘 다 Juniper
스타일이고 지목하는 제품만 다른데, 이것이 매처의 제품 단위
정밀도를 보여줍니다: 샘플 2의 MX 전용 권고는 QFX5110을 건드리지
않고, 샘플 5는 그것을 적중합니다. 샘플 6과 7은 평범한 버전
목록으로는 다룰 수 없는, 실제 권고가 취하는 두 가지 형태를
커버합니다: 서술형 버전 경계(샘플 6)와 구성 조건(샘플 7, Arista
0201 패턴).

샘플 인벤토리(`samples/inventory_sample.txt`): 지어낸 장비 9대
(Catalyst 9300 ×3, Nexus 3064, QFX5110, Arista 7050 ×2,
ASR1002-X, MX480), 한 줄에 하나씩 `hostname, model, OS version`
형식. 라이브 실행에서는 같은 형식의 본인 내보내기 파일로
교체하세요.

## Mock Mode

Mock Mode는 지름길이 아니라 기능입니다:

- `CLOCKED_API_KEY`가 **없으면**, 번들 샘플 7개는
  `mock_responses.json`의 canned 응답으로 실행됩니다 — 실제 SDK
  응답과 정확히 같은 형태이며, UI에 "Demo data" 배너가
  표시됩니다.
- Mock Mode에서 **임의의 텍스트**를 붙여넣어도 판정은 나오지
  **않습니다** — 앱은 실시간 분석에는 키가 필요하다고 솔직히
  밝힙니다. Mock Mode는 판정을 절대 지어내지 않습니다.

## 프로젝트 구성

```
app.py               Streamlit UI only (Batch + Paste modes, EN/KO)
triage.py            All Clocked SDK access, matcher, verdict composition
batch.py             Batch support: CSV inventory parsing, advisory fetching, listing harvester, NVD/KEV feed collectors, vendor full-text tracing (CSAF/JSA/CNA), upload conversion, batch runners
mock_responses.json  Canned Extract/Decide/Verify responses per sample
samples/             7 synthetic advisories + sample inventory + NVD/KEV/CSAF/CNA fixtures (real public data, trimmed)
tests/test_triage.py Offline pytest suite (matcher + verdict composition)
tests/test_app.py    AppTest suite (paste-mode widget state)
tests/test_batch.py  Offline pytest suite (CSV, links, fetching, batch, batch UI)
tests/test_feeds.py  Offline pytest suite (feed collectors, fleet-wide vendors, fixtures, uploads, items runner, feeds/uploads UI)
tests/test_trace.py  Offline pytest suite (vendor tracing routes, CNA fallback, caps, Mock Mode fixtures)
.devcontainer/       One-click GitHub Codespaces environment (runs the app on port 8501)
DEMO_SCRIPT.md       90-second demo video shot list
```

## 테스트

```bash
pip install pytest
pytest -q
```

이 스위트는 모의 데이터로 완전히 오프라인 실행됩니다: 정확 /
범위 / 와일드카드 / 파싱 불가 / 제품 없음 매처 케이스, 제약
파싱과 비교(접미사 모호성 케이스 포함), 적용 조건 게이트,
grounding 뒤집기, 낮은 충분성 강등, 그리고 7개 샘플 전체에 대한
영어·한국어 모의 파이프라인. 배치 스위트는 CSV 파싱(UTF-8 BOM,
CP949, 세미콜론/탭 구분자, 한국어 헤더, 벤더 접두사, 건너뛴 행,
위치 기반 폴백), 링크 목록 정리와 캡, HTML→텍스트 추출, stub
fetcher를 주입한 배치 러너(가져오기 실패 하나가 배치를 중단시키지
않음), 두 입력 모드에 대한 AppTest 커버리지를 다룹니다.

## 제한 사항

- **버전 의미론은 수치 기반이며 벤더를 인식하지 않습니다.**
  명시 버전은 정확 문자열, 와일드카드, 수치 범위로 일치하고,
  서술형 경계("prior to X", "X and earlier", 수정 릴리스로 한정된
  트레인)는 제약으로 정규화되어 수치로 비교됩니다. 아직
  모델링하지 않는 것: 수치 부분이 동점일 때의 문자 접미사 순서
  (EOS `4.30.5F` 대 `4.30.5M`은 설계상 CANNOT DETERMINE), 명시된
  트레인을 넘어서는 트레인/브랜치 동등성, 번들 이미지 버전 관리.
- **적용 조건은 표면화만 하고 해소하지는 않습니다.** 인벤토리
  형식은 모델과 OS 버전만 담으므로, "TerminAttr configured for
  CVP" 같은 조건은 그것만으로 확인할 수 없습니다; 도구는 판정을
  CANNOT DETERMINE으로 게이트하고 장비에서 정확히 무엇을
  확인해야 하는지 알려줍니다. 구성 인벤토리를 제공하면 그런
  판정도 해소될 수 있을 것입니다.
- **배치 가져오기는 최선 노력(best-effort)입니다.** 배치 모드는
  권고 페이지를 직접 다운로드합니다; 로그인, 봇 차단벽, 무거운
  JavaScript 렌더링 뒤에 있는 페이지는 `FETCH FAILED` 행으로
  돌아오거나 부분적인 텍스트만 가져올 수 있습니다(그러면 솔직하게
  CANNOT DETERMINE 쪽으로 기웁니다). 그런 경우 붙여넣기 모드가
  폴백입니다.
- **목록 자동 수집도 최선 노력이, 그 사실을 솔직히 밝힙니다.**
  서버 렌더링 목록은 잘 수집됩니다; 봇 챌린지 뒤의 포털(실측:
  Arista)은 "blocked"로 보고하고, JavaScript로 렌더링되는 포털
  (실측: Cisco PSIRT, Juniper)은 "no links found"로 보고합니다 —
  두 경우 모두 UI는 결과를 지어내는 대신 링크 목록 모드를
  안내합니다. **취약점 피드**와 **권고 파일 업로드** 소스는 바로
  그런 포털을 위해 존재합니다: NVD/KEV는 공식 기계 판독
  채널이고, 업로드는 운영자 본인의 브라우저가 수집을 대신하게
  합니다.
- **피드 커버리지는 키워드 형태이며 최신 우선입니다.** NVD 소스는
  최대 4개의 키워드 질의를 내보내고(벤더는 장비 수 기준
  우선순위), 최근 119일 이내에 발행된 CVE로 제한하며(API의 날짜
  구간 캡; 이것 없이는 API가 가장 오래된 일치를 먼저 반환합니다),
  질의당 10건, 최신순, 최대 15건까지입니다 — 제품별 CPE를 전수
  탐색하는 방식은 아닙니다. KEV는 실제 악용이 확인된 취약점만
  나열합니다. 피드는 벤더 권고를 보완할 뿐 대체하지 않습니다.
- **벤더 추적은 캡이 있고 최선 노력입니다.** 실행당 최대 10건의
  피드 항목이 제조사 원문까지 추적되며, 실제 악용 중(KEV)인
  항목이 우선합니다; 나머지는 피드 텍스트로 판정됩니다.
  2026-11-07 실측: Cisco CSAF JSON과 CNA 미러는 완전한 구조화
  데이터를 반환한 반면, Juniper의 JSA 포털은 직접 가져오기에
  45자짜리 셸로 응답했습니다 — ≥ 400자 채택 규칙이 이를
  거부했고, 대신 CNA 레코드가 영향 버전 범위를 제공했습니다.
  Arista의 CSAF 엔드포인트는 자동 가져오기에 봇 챌린지를 걸 수
  있으며, 같은 CNA 폴백이 적용됩니다. 실패한 추적은 추적된
  것처럼 꾸며지지 않습니다.
- **관련성 프리필터는 거친 스크린입니다.** 인벤토리의 제품 공간을
  전혀 언급하지 않는 권고만 떨어뜨립니다; 장비별 판정 로직은
  그대로이며, 필터는 실행마다 끌 수 있습니다.
- **데이터를 보관하지 않습니다.** 앱은 아무것도 저장하지
  않습니다; 권고와 인벤토리 텍스트는 실행 중에만 존재합니다
  (라이브 모드에서는 Clocked API로 전송됩니다).
- 매처는 의도적으로 보수적입니다: 증명할 수 없는 것은 무엇이든
  설계상 CANNOT DETERMINE이 됩니다.

## 배포

라이브 데모 https://advisory-triage.streamlit.app/ 는 이 저장소의
`main` 브랜치에서 자동 배포됩니다(Streamlit Cloud). Clocked API
키는 Streamlit secret(`CLOCKED_API_KEY`)으로 배포 환경에
제공되며, 저장소에 커밋되지 않습니다.
