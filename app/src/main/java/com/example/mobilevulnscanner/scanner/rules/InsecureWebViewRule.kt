package com.example.mobilevulnscanner.scanner.rules

import com.example.mobilevulnscanner.scanner.model.Vulnerability
import com.example.mobilevulnscanner.scanner.model.Vulnerability.Severity
import java.io.File
import java.util.zip.ZipFile

/**
 * WebView 설정을 정적 분석으로 검사합니다.
 * 1) setJavaScriptEnabled(true) 호출
 * 2) loadUrl("http://...") 와 같이 검증 없이 외부 URL을 로드
 */
class InsecureWebViewRule : ScanRule {
    override val ruleId = "InsecureWebViewRule"

    override fun scan(apkFile: File): List<Vulnerability> {
        val vulns = mutableListOf<Vulnerability>()

        ZipFile(apkFile).use { zip ->
            // classes.dex 에 있는 문자열 테이블을 간단히 검색
            val dexEntry = zip.getEntry("classes.dex")
            if (dexEntry != null) {
                val bytes = zip.getInputStream(dexEntry).readBytes()
                // 바이너리에서 문자열로 변환 (embedded UTF-8 strings)
                val text = String(bytes, Charsets.UTF_8)

                // 1) JavaScriptEnabled 검사
                if (text.contains("setJavaScriptEnabled(true)")) {
                    vulns += Vulnerability(
                        ruleId     = ruleId,
                        description= "WebView에서 자바스크립트 실행이 허용되었습니다.",
                        severity   = Severity.MEDIUM,
                        detail     = "발견된 설정: setJavaScriptEnabled(true)"
                    )
                }
                // 2) 외부 HTTP URL 로드 검사
                //    단순히 "loadUrl(\"http://" 패턴을 찾아냅니다.
                val regex = Regex("""loadUrl\(\s*"(http://[^"]+)"""")
                regex.findAll(text).forEach { match ->
                    val url = match.groupValues[1]
                    vulns += Vulnerability(
                        ruleId     = ruleId,
                        description= "검증 없는 외부 URL이 WebView에 로드됩니다.",
                        severity   = Severity.MEDIUM,
                        detail     = "발견된 URL: $url"
                    )
                }
            }
        }

        return vulns
    }
}
