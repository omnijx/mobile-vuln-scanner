package com.example.mobilevulnscanner.scanner.rules

import com.example.mobilevulnscanner.scanner.model.Vulnerability
import com.example.mobilevulnscanner.scanner.model.Vulnerability.Severity
import net.dongliu.apk.parser.ApkFile
import org.xmlpull.v1.XmlPullParser
import java.io.File

class ManifestRule : ScanRule {
    override val ruleId = "ManifestRule"

    // 위험 권한 목록
    private val dangerous = listOf(
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.READ_SMS",
        "android.permission.WRITE_EXTERNAL_STORAGE"
    )

    override fun scan(apkFile: File): List<Vulnerability> {
        val found = mutableListOf<Vulnerability>()
        ApkFile(apkFile).use { apk ->
            val xml = apk.manifestXml
            val parser = android.util.Xml.newPullParser().apply {
                setInput(xml.byteInputStream(), null)
            }
            var event = parser.eventType
            while (event != XmlPullParser.END_DOCUMENT) {
                if (event == XmlPullParser.START_TAG && parser.name == "uses-permission") {
                    parser.getAttributeValue(
                        "http://schemas.android.com/apk/res/android",
                        "name"
                    )?.let { perm ->
                        if (perm in dangerous) {
                            found += Vulnerability(
                                ruleId     = ruleId,
                                description= "APK 매니페스트에 위험 권한이 설정되었습니다.",
                                severity   = Severity.HIGH,
                                detail     = "발견된 권한: $perm"
                            )
                        }
                    }
                }
                event = parser.next()
            }
        }
        return found
    }
}
