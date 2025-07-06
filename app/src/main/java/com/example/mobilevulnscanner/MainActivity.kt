package com.example.mobilevulnscanner

import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts.GetContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.example.mobilevulnscanner.scanner.StaticAnalyzer
import com.example.mobilevulnscanner.scanner.model.Vulnerability
import com.example.mobilevulnscanner.scanner.model.Vulnerability.Severity
import com.example.mobilevulnscanner.scanner.rules.DebuggableFlagRule
import com.example.mobilevulnscanner.scanner.rules.ExportedComponentRule
import com.example.mobilevulnscanner.scanner.rules.HardcodedSecretRule
import com.example.mobilevulnscanner.scanner.rules.InsecureWebViewRule
import com.example.mobilevulnscanner.scanner.rules.ManifestRule
import com.example.mobilevulnscanner.ui.theme.MobileVulnScannerTheme
import java.io.File
import java.io.FileOutputStream

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            MobileVulnScannerTheme {
                var selectedApkUri by remember { mutableStateOf<Uri?>(null) }
                var scanResults by remember { mutableStateOf<List<Vulnerability>>(emptyList()) }

                // APK 선택 런처
                val apkPicker = rememberLauncherForActivityResult(GetContent()) { uri ->
                    selectedApkUri = uri
                }

                // APK URI가 변경되면 스캔 실행
                LaunchedEffect(selectedApkUri) {
                    selectedApkUri?.let { uri ->
                        contentResolver.openInputStream(uri)?.use { input ->
                            val tempFile = File(cacheDir, "tmp_scan.apk")
                            FileOutputStream(tempFile).use { out -> input.copyTo(out) }

                            val analyzer = StaticAnalyzer(
                                listOf(
                                    ManifestRule(),
                                    HardcodedSecretRule(),
                                    DebuggableFlagRule(),
                                    ExportedComponentRule(),
                                    InsecureWebViewRule()    // 새로 추가
                                )
                            )
                            scanResults = analyzer.analyze(tempFile)
                            tempFile.delete()
                        }
                    }
                }

                Scaffold { inner ->
                    Column(
                        Modifier
                            .fillMaxSize()
                            .padding(inner)
                            .padding(16.dp)
                    ) {
                        // APK 선택 버튼
                        Button(onClick = {
                            apkPicker.launch("application/vnd.android.package-archive")
                        }) {
                            Text("APK 파일 선택")
                        }

                        Spacer(Modifier.height(12.dp))

                        // 취약점 심각도 요약 뱃지
                        SummaryRow(scanResults)

                        Spacer(Modifier.height(12.dp))

                        // 선택된 APK 파일 이름 표시
                        Text(
                            text = selectedApkUri?.lastPathSegment ?: "선택된 APK 없음",
                            style = MaterialTheme.typography.bodyMedium
                        )

                        Spacer(Modifier.height(8.dp))

                        // 룰별로 결과 그룹핑
                        val grouped = scanResults.groupBy { it.ruleId }

                        // 취약점 리스트
                        LazyColumn(
                            Modifier
                                .weight(1f)
                                .fillMaxWidth()
                        ) {
                            // 1) ManifestRule
                            item {
                                Text(
                                    text = "ManifestRule",
                                    style = MaterialTheme.typography.titleLarge,
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .background(Color(0xFFE0E0E0))
                                        .padding(8.dp)
                                )
                            }
                            grouped["ManifestRule"]?.let { list ->
                                items(list) { vuln -> VulnerabilityCard(vuln) }
                            }

                            // 2) HardcodedSecretRule
                            item {
                                Spacer(Modifier.height(16.dp))
                                Text(
                                    text = "HardcodedSecretRule",
                                    style = MaterialTheme.typography.titleLarge,
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .background(Color(0xFFE0E0E0))
                                        .padding(8.dp)
                                )
                            }
                            grouped["HardcodedSecretRule"]?.let { list ->
                                items(list) { vuln -> VulnerabilityCard(vuln) }
                            }

                            // 3) DebuggableFlagRule
                            item {
                                Spacer(Modifier.height(16.dp))
                                Text(
                                    text = "DebuggableFlagRule",
                                    style = MaterialTheme.typography.titleLarge,
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .background(Color(0xFFE0E0E0))
                                        .padding(8.dp)
                                )
                            }
                            grouped["DebuggableFlagRule"]?.let { list ->
                                items(list) { vuln -> VulnerabilityCard(vuln) }
                            }

                            // 4) ExportedComponentRule
                            item {
                                Spacer(Modifier.height(16.dp))
                                Text(
                                    text = "ExportedComponentRule",
                                    style = MaterialTheme.typography.titleLarge,
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .background(Color(0xFFE0E0E0))
                                        .padding(8.dp)
                                )
                            }
                            grouped["ExportedComponentRule"]?.let { list ->
                                items(list) { vuln -> VulnerabilityCard(vuln) }
                            }

                            // 5) InsecureWebViewRule
                            item {
                                Spacer(Modifier.height(16.dp))
                                Text(
                                    text = "InsecureWebViewRule",
                                    style = MaterialTheme.typography.titleLarge,
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .background(Color(0xFFE0E0E0))
                                        .padding(8.dp)
                                )
                            }
                            grouped["InsecureWebViewRule"]?.let { list ->
                                items(list) { vuln -> VulnerabilityCard(vuln) }
                            }

                            // 결과 없을 때 메시지
                            if (scanResults.isEmpty()) {
                                item {
                                    Spacer(Modifier.height(16.dp))
                                    Text(
                                        "취약점이 발견되지 않았습니다.",
                                        style = MaterialTheme.typography.bodyLarge,
                                        modifier = Modifier.padding(16.dp)
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SummaryRow(results: List<Vulnerability>) {
    val counts: Map<Severity, Int> = remember(results) {
        mapOf(
            Severity.HIGH   to results.count { it.severity == Severity.HIGH },
            Severity.MEDIUM to results.count { it.severity == Severity.MEDIUM },
            Severity.LOW    to results.count { it.severity == Severity.LOW }
        )
    }
    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        counts.forEach { (sev, cnt) ->
            Text(
                text = "${sev.name}: $cnt",
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier
                    .background(Color.LightGray, shape = MaterialTheme.shapes.small)
                    .padding(horizontal = 8.dp, vertical = 4.dp)
            )
        }
    }
}

@Composable
private fun VulnerabilityCard(vuln: Vulnerability) {
    val highlight = when (vuln.severity) {
        Severity.HIGH   -> Color(0xFFFB8C00)
        Severity.MEDIUM -> Color(0xFF1976D2)
        Severity.LOW    -> Color(0xFF388E3C)
        else            -> Color.Gray
    }

    Card(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
    ) {
        Column(Modifier.padding(12.dp)) {
            Text(
                text = vuln.ruleId,
                style = MaterialTheme.typography.titleSmall,
                color = Color.DarkGray
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = vuln.description,
                style = MaterialTheme.typography.bodyMedium,
                color = Color.Black
            )
            Spacer(Modifier.height(6.dp))
            vuln.detail?.let { detail ->
                Text(
                    text = detail,
                    style = MaterialTheme.typography.bodySmall,
                    color = highlight
                )
            }
        }
    }
}
