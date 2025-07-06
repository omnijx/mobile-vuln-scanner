package com.example.mobilevulnscanner.scanner.rules
import com.example.mobilevulnscanner.scanner.model.Vulnerability
import com.example.mobilevulnscanner.scanner.model.Vulnerability.Severity
import com.example.mobilevulnscanner.scanner.rules.ScanRule
import net.dongliu.apk.parser.ApkFile
import java.io.File
import java.io.StringReader
import javax.xml.parsers.DocumentBuilderFactory
import org.xml.sax.InputSource

class DebuggableFlagRule : ScanRule {
    override val ruleId = "DebuggableFlagRule"

    override fun scan(apkFile: File): List<Vulnerability> {
        val vulns = mutableListOf<Vulnerability>()

        ApkFile(apkFile).use { apk ->
            // 1) 바이너리 XML → 텍스트 XML로
            val manifestXmlText = apk.manifestXml

            // 2) 텍스트 XML을 DOM으로 파싱
            val doc = DocumentBuilderFactory.newInstance().apply {
                isNamespaceAware = true
            }.newDocumentBuilder()
                .parse(InputSource(StringReader(manifestXmlText)))

            // 3) <application android:debuggable="true"> 검사
            val appNodes = doc.getElementsByTagName("application")
            if (appNodes.length > 0) {
                val application = appNodes.item(0)
                val debugAttr = application.attributes
                    .getNamedItem("android:debuggable")
                    ?.nodeValue

                if (debugAttr == "true") {
                    vulns += Vulnerability(
                        ruleId     = ruleId,
                        description= "APK가 디버깅 모드로 빌드되었습니다.",
                        severity   = Severity.HIGH,
                        detail     = "AndroidManifest.xml의 <application>에 android:debuggable=\"true\"가 설정되어 있습니다."
                    )
                }
            }
        }

        return vulns
    }
}
