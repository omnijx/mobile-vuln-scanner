package com.example.mobilevulnscanner.scanner.rules

import com.example.mobilevulnscanner.scanner.model.Vulnerability
import com.example.mobilevulnscanner.scanner.model.Vulnerability.Severity
import net.dongliu.apk.parser.ApkFile
import java.io.File

class HardcodedSecretRule : ScanRule {
    override val ruleId = "HardcodedSecretRule"

    // 탐지할 키워드 목록
    private val keywords = listOf("API_KEY", "PASSWORD", "SECRET", "ACCESS_TOKEN")

    override fun scan(apkFile: File): List<Vulnerability> {
        val results = mutableListOf<Vulnerability>()
        ApkFile(apkFile).use { apk ->
            val allText = apk.manifestXml
            keywords.forEach { kw ->
                if (allText.contains(kw, ignoreCase = true)) {
                    results += Vulnerability(
                        ruleId     = ruleId,
                        description= "코드/매니페스트에 민감 정보가 하드코딩되어 있습니다.",
                        severity   = Severity.MEDIUM,
                        detail     = "발견된 키워드: $kw"
                    )
                }
            }
        }
        return results
    }
}
