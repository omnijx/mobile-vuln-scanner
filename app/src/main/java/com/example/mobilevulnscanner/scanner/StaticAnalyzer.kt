package com.example.mobilevulnscanner.scanner

import com.example.mobilevulnscanner.scanner.rules.ScanRule
import com.example.mobilevulnscanner.scanner.model.Vulnerability
import java.io.File

class StaticAnalyzer(private val rules: List<ScanRule>) {
    fun analyze(apkFile: File): List<Vulnerability> =
        rules.flatMap { it.scan(apkFile) }
}
