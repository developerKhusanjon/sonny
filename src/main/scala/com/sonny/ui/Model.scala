package com.sonny.ui

import tyrian.Cmd

import java.time.LocalDateTime
import scala.language.postfixOps

enum Tab:
  case Dashboard, Viruses, Threats, Vulnerabilities, Traffic

enum FilterType:
  case All, High, Medium, Low, Critical
  case Server, Endpoint, Network
  case Anomaly, Normal

case class VirusData(
  id: String,
  timestamp: String,
  fileName: String,
  virusType: String,
  severity: String,
  location: String,
  status: String
  )

case class ThreatData(
  id: String,
  timestamp: String,
  source: String,
  target: String,
  threatType: String,
  severity: String,
  status: String)

case class VulnData(
  id: String,
  system: String,
  description: String,
  severity: String,
  discoveryDate: String,
  status: String)

case class TrafficData(
  id: String,
  timestamp: String,
  sourceIp: String,
  destIp: String,
  protocol: String,
  volume: String,
  isAnomaly: Boolean)

final case class Model(
  activeTab: Tab,
  virusData: List[VirusData],
  threatData: List[ThreatData],
  vulnData: List[VulnData],
  trafficData: List[TrafficData],
  error: Option[String],
  isLoading: Boolean,
  currentFilter: FilterType,
  lastUpdated: LocalDateTime)

object Model:
  def initial: Model = Model(
    activeTab = Tab.Dashboard,
    virusData = Nil,
    threatData = Nil,
    vulnData = Nil,
    trafficData = Nil,
    error = None,
    isLoading = true,
    currentFilter = FilterType.All,
    lastUpdated = LocalDateTime.now()
  )

  def initialCmd: Cmd.Emit[Msg] =
    RestApiClient.fetchDataForTab(initial.activeTab)
    
//  private def generateDummyVirusData(): List[VirusData] =
//    List(
//      VirusData("V1", "2025-05-15 10:23:45", "invoice.pdf", "Trojan.PDF.Agent", "High", "192.168.1.105", "Quarantined"),
//      VirusData("V2", "2025-05-15 09:17:32", "setup.exe", "Win32.Emotet", "High", "192.168.1.107", "Blocked"),
//      VirusData("V3", "2025-05-15 08:45:19", "document.docx", "Macro.Downloader", "Medium", "192.168.1.112", "Quarantined"),
//      VirusData("V4", "2025-05-14 22:31:05", "update.zip", "Backdoor.Generic", "High", "192.168.1.118", "Removed"),
//      VirusData("V5", "2025-05-14 18:12:57", "image.jpg", "JS.Downloader", "Medium", "192.168.1.124", "Investigating"),
//      VirusData("V6", "2025-05-14 14:05:22", "report.xlsx", "XLS.Dropper", "Low", "192.168.1.132", "Quarantined")
//    )

  def generateDummyThreatData(): List[ThreatData] =
    List(
      ThreatData("T1", "2025-05-15 11:42:18", "203.0.113.42", "192.168.1.5", "Intrusion Attempt", "High", "Blocked"),
      ThreatData("T2", "2025-05-15 10:37:22", "198.51.100.76", "192.168.1.110", "Data Exfiltration", "High", "Investigating"),
      ThreatData("T3", "2025-05-15 09:21:47", "192.168.1.107", "74.125.24.100", "Suspicious Connection", "Medium", "Monitoring"),
      ThreatData("T4", "2025-05-14 23:17:33", "45.33.20.148", "192.168.1.1", "DoS Attack", "High", "Mitigated"),
      ThreatData("T5", "2025-05-14 20:05:12", "192.168.1.118", "91.189.92.38", "C2 Communication", "High", "Blocked"),
      ThreatData("T6", "2025-05-14 15:42:08", "104.244.42.193", "192.168.1.120", "Scanning Activity", "Low", "Monitoring")
    )

//  private def generateDummyVulnData(): List[VulnData] =
//    List(
//      VulnData("CVE-2025-1234", "Web Server", "SQL Injection in login form", "Critical", "2025-05-14", "Open"),
//      VulnData("CVE-2025-2345", "Mail Server", "TLS vulnerability in OpenSSL", "High", "2025-05-13", "In Progress"),
//      VulnData("CVE-2025-3456", "FileShare", "Privilege escalation in user management", "Medium", "2025-05-12", "Open"),
//      VulnData("CVE-2025-4567", "Database", "Remote code execution in stored procedures", "Critical", "2025-05-11", "Patched"),
//      VulnData("CVE-2025-5678", "Firewall", "Authentication bypass in admin panel", "High", "2025-05-10", "In Progress"),
//      VulnData("CVE-2025-6789", "Load Balancer", "DoS vulnerability in packet handling", "Medium", "2025-05-09", "Scheduled")
//    )
//
//  private def generateDummyTrafficData(): List[TrafficData] =
//    List(
//      TrafficData("TR1", "2025-05-15 11:57:42", "192.168.1.107", "203.0.113.42", "HTTPS", "458", true),
//      TrafficData("TR2", "2025-05-15 11:50:33", "192.168.1.110", "192.168.1.1", "DNS", "32", false),
//      TrafficData("TR3", "2025-05-15 11:42:18", "192.168.1.105", "172.217.20.174", "HTTPS", "215", false),
//      TrafficData("TR4", "2025-05-15 11:35:26", "192.168.1.118", "91.189.92.38", "HTTP", "1240", true),
//      TrafficData("TR5", "2025-05-15 11:27:51", "192.168.1.112", "74.125.24.100", "HTTPS", "187", false),
//      TrafficData("TR6", "2025-05-15 11:20:04", "198.51.100.76", "192.168.1.1", "ICMP", "543", true)
//    )
end Model