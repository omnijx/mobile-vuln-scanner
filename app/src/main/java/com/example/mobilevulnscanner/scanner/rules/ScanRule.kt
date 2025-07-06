package com.example.mobilevulnscanner.scanner.rules

import com.example.mobilevulnscanner.scanner.model.Vulnerability
import java.io.File

interface ScanRule {
    val ruleId: String
    fun scan(apkFile: File): List<Vulnerability>
}
