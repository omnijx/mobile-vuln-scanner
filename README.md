# MobileVulnScanner

[![Build Status](https://img.shields.io/github/actions/workflow/status/yourusername/MobileVulnScanner/android.yml)](https://github.com/yourusername/MobileVulnScanner/actions)  
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

MobileVulnScanner는 Android APK 파일을 대상으로 **정적 분석**을 수행하여 주요 보안 취약점을 찾아주는 경량 데스크탑/모바일 앱입니다.  
Jetpack Compose 기반의 직관적인 UI로 누구나 쉽게 APK를 선택하고, 취약점 스캔 결과를 한눈에 확인할 수 있습니다.

---

## 📖 목차

1. [소개](#소개)  
2. [주요 기능](#주요-기능)  
3. [아키텍처 및 컴포넌트](#아키텍처-및-컴포넌트)  
4. [설치 및 실행](#설치-및-실행)  
5. [사용 예시](#사용-예시)  
6. [프로젝트 구조](#프로젝트-구조)  
7. [테스트](#테스트)  
8. [Contributing](#contributing)  
9. [Roadmap](#roadmap)  
10. [License](#license)  

---

## 소개

현대 모바일 앱은 복잡한 기능과 네트워크 연동으로 인해 다양한 보안 리스크에 노출될 수 있습니다.  
MobileVulnScanner는 APK 내부를 정적으로 분석하여 다음과 같은 취약점을 자동으로 검출합니다:

- **매니페스트 위험 권한**  
- **평문 HTTP 통신 허용**  
- **디버깅 모드 활성화**  
- **외부 노출 컴포넌트**  
- **하드코딩된 API 키/비밀번호 등**  
- **취약 스토리지 및 암호화 사용**  
- **WebView 보안 설정**  
- **SSL/TLS 검증 무력화**

별도의 설정 없이 “APK 선택”만으로 즉시 스캔 가능하며, 실시간 요약·필터링·상세 보기 기능을 제공합니다.

---

## 주요 기능

- 🔒 **정적 분석 룰 10종**  
  1. ManifestRule (위험 권한)  
  2. AllowBackupFlagRule (allowBackup)  
  3. CleartextTrafficRule (평문 HTTP)  
  4. DebuggableFlagRule (디버깅 모드)  
  5. ExportedComponentRule (외부 노출 컴포넌트)  
  6. HardcodedSecretRule (하드코딩된 민감 정보)  
  7. InsecureStorageRule (취약 스토리지)  
  8. WeakCryptoUsageRule (약한 암호화 알고리즘)  
  9. InsecureWebViewRule (WebView 보안 설정)  
  10. InsecureTrustManagerRule (SSL/TLS 검증 무력화)

- 📊 **실시간 요약 대시보드**  
  - HIGH / MEDIUM / LOW 심각도별 총 건수 표시  

- 🔍 **룰 검색 & 필터링**  
  - 검색창에 룰 이름(키워드) 입력 시 해당 섹션만 노출  

- 🎛️ **사용자 친화적 결과 탐색**  
  - 룰별 접기/펼치기(Accordion)  
  - 각 취약점 카드에서 설명 및 상세 패턴/위치 표시  

- ⚙️ **환경변수 기반 릴리즈 서명**  
  - CI/CD 연동 시 민감 정보 노출 없이 자동 서명 가능  

---

## 아키텍처 및 컴포넌트

┌─────────────────────┐ ┌────────────────────┐
│ MainActivity.kt │ → │ StaticAnalyzer │
│ (Compose UI / UX) │ │(ScanRule 실행 매니저)│
└─────────────────────┘ └────────────────────┘
↓ ↓
사용자 선택 APK ScanRule 리스트 순회
│ │
↓ ↓
scanResults: List<Vulnerability> ←─ rules.flatMap { it.scan() }
↓
UI: SummaryRow, CollapsibleSection, VulnerabilityCard

kotlin
복사
편집

- **MainActivity.kt**: APK 선택, `LaunchedEffect`로 분석 트리거, UI 컴포저블 배치  
- **StaticAnalyzer**:
  ```kotlin
  class StaticAnalyzer(private val rules: List<ScanRule>) {
      fun analyze(apkFile: File): List<Vulnerability> =
          rules.flatMap { it.scan(apkFile) }
  }
Vulnerability 모델:

kotlin
복사
편집
data class Vulnerability(
    val ruleId: String,
    val description: String,
    val severity: Severity,
    val detail: String
) {
    enum class Severity { CRITICAL, HIGH, MEDIUM, LOW }
}
ScanRule 인터페이스:

kotlin
복사
편집
interface ScanRule {
    val ruleId: String
    fun scan(apkFile: File): List<Vulnerability>
}
설치 및 실행
사전 요구사항

Android Studio Arctic Fox 이상

JDK 11

레포지토리 복제

bash
복사
편집
git clone https://github.com/yourusername/MobileVulnScanner.git
cd MobileVulnScanner
환경 변수 설정 (릴리즈 서명용)

bash
복사
편집
export KEYSTORE_PATH=/path/to/keystore.jks
export KEYSTORE_PASSWORD=your_store_password
export KEY_ALIAS=mobilevulnscanner
export KEY_PASSWORD=your_key_password
앱 빌드 & 실행

bash
복사
편집
./gradlew assembleDebug
APK 선택: 앱 실행 후 “APK 파일 선택” 버튼 클릭

자동 분석: 선택 즉시 스캔 시작 → 결과 확인

사용 예시 (스크린샷)

APK 선택 및 검색창, 요약 영역


룰별 Accordion, 취약점 카드 표시

프로젝트 구조
swift
복사
편집
MobileVulnScanner/
├─ app/
│  ├─ src/main/java/com/example/mobilevulnscanner/
│  │  ├─ MainActivity.kt
│  │  ├─ ui/
│  │  │  ├─ CollapsibleSection.kt
│  │  │  ├─ SummaryRow.kt
│  │  │  └─ VulnerabilityCard.kt
│  │  └─ scanner/
│  │     ├─ StaticAnalyzer.kt
│  │     ├─ model/
│  │     │  └─ Vulnerability.kt
│  │     └─ rules/
│  │        ├─ ManifestRule.kt
│  │        ├─ AllowBackupFlagRule.kt
│  │        ├─ CleartextTrafficRule.kt
│  │        ├─ DebuggableFlagRule.kt
│  │        ├─ ExportedComponentRule.kt
│  │        ├─ HardcodedSecretRule.kt
│  │        ├─ InsecureStorageRule.kt
│  │        ├─ WeakCryptoUsageRule.kt
│  │        ├─ InsecureWebViewRule.kt
│  │        └─ InsecureTrustManagerRule.kt
│  └─ build.gradle.kts
├─ docs/
│  └─ images/
│     ├─ main_screen.png
│     └─ results_screen.png
├─ LICENSE
└─ README.md
테스트
단위 테스트:

StaticAnalyzer 및 각 ScanRule 로직

apk-parser 모킹

기기 테스트:

Android 에뮬레이터(API 24~35)

실제 기기(Android 7.0 이상)
