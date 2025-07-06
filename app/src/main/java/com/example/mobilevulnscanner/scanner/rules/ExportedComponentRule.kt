package com.example.mobilevulnscanner.scanner.rules

import com.example.mobilevulnscanner.scanner.model.Vulnerability
import com.example.mobilevulnscanner.scanner.model.Vulnerability.Severity
import net.dongliu.apk.parser.ApkFile
import org.xmlpull.v1.XmlPullParser
import java.io.File

class ExportedComponentRule : ScanRule {
    override val ruleId = "ExportedComponentRule"

    // 검사할 컴포넌트 태그명
    private val tags = setOf("activity", "service", "receiver", "provider")

    override fun scan(apkFile: File): List<Vulnerability> {
        val vulns = mutableListOf<Vulnerability>()

        ApkFile(apkFile).use { apk ->
            val xml = apk.manifestXml
            val parser = android.util.Xml.newPullParser().apply {
                setInput(xml.byteInputStream(), null)
            }

            // 파싱 루프
            var event = parser.eventType
            while (event != XmlPullParser.END_DOCUMENT) {
                if (event == XmlPullParser.START_TAG && parser.name in tags) {
                    // 컴포넌트 시작 지점
                    val tagName = parser.name
                    val compName = parser.getAttributeValue(
                        "http://schemas.android.com/apk/res/android",
                        "name"
                    ) ?: tagName

                    // android:exported 속성 값 (null=명시 안 됨)
                    val exportedAttr = parser.getAttributeValue(
                        "http://schemas.android.com/apk/res/android",
                        "exported"
                    )

                    // 이 컴포넌트 블록 안에서 intent-filter가 하나라도 있는지 확인하기 위해
                    var hasIntentFilter = false
                    // 내부 태그까지 내려가면서 intent-filter 체크
                    var depth = 1
                    while (depth > 0) {
                        event = parser.next()
                        when (event) {
                            XmlPullParser.START_TAG -> {
                                if (parser.name == "intent-filter") {
                                    hasIntentFilter = true
                                }
                                depth++
                            }
                            XmlPullParser.END_TAG -> {
                                depth--
                            }
                        }
                    }

                    // 외부 노출 판단:
                    // 1) 명시적으로 exported="true"
                    // 2) exported 속성 없고 intent-filter가 있으면 기본값=true (Android 12 이하)
                    val isExported = exportedAttr == "true" ||
                            (exportedAttr == null && hasIntentFilter)

                    if (isExported) {
                        vulns += Vulnerability(
                            ruleId     = ruleId,
                            description= "AndroidManifest에 외부 노출 컴포넌트가 설정되었습니다.",
                            severity   = Severity.MEDIUM,
                            detail     = "발견된 컴포넌트: $compName"
                        )
                    }

                    // 다음 START_TAG 까지 depth를 1로 초기화했으니, 루프 계속
                    event = parser.eventType
                    continue
                }
                event = parser.next()
            }
        }

        return vulns
    }
}
