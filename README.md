# MobileVulnScanner

[![Build Status](https://img.shields.io/github/actions/workflow/status/omnijx/mobile-vuln-scanner/android.yml)](https://github.com/omnijx/mobile-vuln-scanner/actions)  
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

MobileVulnScanner는 Android APK 파일을 대상으로 **정적 분석**을 수행하여 주요 보안 취약점을 찾아주는 경량 앱입니다.  
Jetpack Compose 기반의 직관적인 UI로 APK 선택부터 결과 확인까지 한 번에 처리할 수 있습니다.

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

현대 모바일 앱은 복잡한 기능과 네트워크 연동으로 다양한 보안 리스크에 노출됩니다.  
MobileVulnScanner는 APK 내부를 정적으로 분석하여 다음 취약점을 자동으로 검출합니다:

- 매니페스트 위험 권한  
- 평문 HTTP 통신 허용  
- 디버깅 모드 활성화  
- 외부 노출 컴포넌트  
- 하드코딩된 민감 정보  
- 취약 스토리지 및 암호화 사용  
- WebView 보안 설정  
- SSL/TLS 검증 무력화

“APK 선택”만으로 즉시 스캔이 시작되고, 실시간 요약·필터링·상세 보기 기능을 제공합니다.

---

## 주요 기능

- 🔒 정적 분석 룰 10종  
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

- 📊 실시간 요약 대시보드 (HIGH / MEDIUM / LOW 건수 표시)  
- 🔍 룰 검색 & 필터링 (키워드 입력 시 해당 섹션만 노출)  
- 🎛️ 결과 탐색 UX (접기/펼치기, 상세 설명 및 패턴 표시)  
- ⚙️ 환경변수 기반 릴리즈 서명 (CI/CD 연동 시 자동 서명)

---

## 아키텍처 및 컴포넌트

```text
┌─────────────────────┐   ┌────────────────────┐
│   MainActivity.kt   │ → │   StaticAnalyzer   │
│  (Compose UI / UX)  │   │ (ScanRule 매니저)  │
└─────────────────────┘   └────────────────────┘
         ↓                         ↓
   사용자 선택 APK          룰 리스트 순회 및 스캔
         │                         │
         ↓                         ↓
scanResults: List<Vulnerability> ← rules.flatMap { it.scan() }
         ↓
UI: SummaryRow, CollapsibleSection, VulnerabilityCard
