# MobileVulnScanner

MobileVulnScanner는 Android APK 파일을 대상으로 **정적 분석**을 수행하여 주요 보안 취약점을 찾아주는 도구입니다.  
Jetpack Compose 기반의 간편한 UI로 APK 선택과 스캔, 결과 확인을 한 번에 할 수 있습니다.

---

## 🔍 주요 기능

- **다양한 보안 룰**  
  - 매니페스트 내 위험 권한 검사  
  - allowBackup 플래그 검사  
  - 평문 HTTP 통신 허용 검사 (usesCleartextTraffic, networkSecurityConfig)  
  - 디버깅 플래그 검사  
  - 외부 노출 컴포넌트(Activity/Service/Receiver/Provider) 검사  
  - 하드코딩된 비밀 정보(API_KEY, PASSWORD 등) 검사  
  - 취약 스토리지 모드 (MODE_WORLD_READABLE/WRITEABLE, 외부 저장소) 검사  
  - 약한 암호화 알고리즘(MD5, SHA-1) 및 ECB 모드 검사  
  - WebView 설정 검사 (JavaScript 허용, HTTP URL 로드)  
  - SSL/TLS 검증 무력화 검사 (TrustManager, HostnameVerifier)  

- **실시간 요약**  
  - HIGH / MEDIUM / LOW 등급별 취약 건수 표시  

- **룰 검색 & 필터링**  
  - 룰 이름으로 빠르게 검색  

- **결과 탐색 UX**  
  - 룰별 접기/펼치기, 상세 설명 및 검출 위치 확인  

<img width="573" height="1259" alt="image" src="https://github.com/user-attachments/assets/c8c7ea7a-bf17-464b-8251-30dd9598951b" />

---

## 🚀 설치 및 실행

1. **사전 준비**  
   - Android Studio Arctic Fox 이상  
   - JDK 11  

2. **레포지토리 복제**  
   ```bash
   git clone https://github.com/yourusername/MobileVulnScanner.git
   cd MobileVulnScanner
