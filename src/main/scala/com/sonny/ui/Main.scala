package com.sonny.ui

import cats.effect.IO
import tyrian.*
import tyrian.Html.*
import tyrian.http.*

import scala.scalajs.js.annotation.*
import scala.concurrent.duration.*

@JSExportTopLevel("Main")
object Main extends TyrianIOApp[Msg, Model]:

  def init(flags: Map[String, String]): (Model, Cmd[IO, Msg]) =
    (Model.initial, Model.initialCmd)

  def update(msg: Msg, model: Model): (Model, Cmd[IO, Msg]) =
    msg match
      case Msg.NoOp =>
        (model, Cmd.None)

      case Msg.UpdateTab(tab) =>
        (model.copy(activeTab = tab), RestApiClient.fetchDataForTab(tab))

      case Msg.FetchData =>
        (model.copy(isLoading = true), RestApiClient.fetchDataForTab(model.activeTab))

      case Msg.ExecuteAction(itemId, actionType, itemType) =>
        // Handle action execution (like quarantine, block, etc.)
        (model, RestApiClient.executeAction(itemId, actionType, itemType))

      case Msg.RequestAnalysis(itemId, itemType) =>
        // Request detailed analysis for an item
        (model, RestApiClient.requestAnalysis(itemId, itemType))

      case Msg.DataResponse(result) =>
        val updatedModel = model.copy(isLoading = false)

        result match
          case Http.Response.Success(data) =>
            // Simulate processing response based on active tab
            val modelWithData = model.activeTab match
              case Tab.Dashboard => updatedModel.copy(
                virusData = DataParser.parseVirusData(data),
                threatData = DataParser.parseThreatData(data),
                vulnData = DataParser.parseVulnData(data),
                trafficData = DataParser.parseTrafficData(data)
              )
              case Tab.Viruses => updatedModel.copy(virusData = DataParser.parseVirusData(data))
              case Tab.Threats => updatedModel.copy(threatData = DataParser.parseThreatData(data))
              case Tab.Vulnerabilities => updatedModel.copy(vulnData = DataParser.parseVulnData(data))
              case Tab.Traffic => updatedModel.copy(trafficData = DataParser.parseTrafficData(data))

            (modelWithData, Cmd.None)

          case Http.Response.Error(code, msg) =>
            (updatedModel.copy(error = Some(s"Error $code: $msg")), Cmd.None)

          case _ =>
            (updatedModel.copy(error = Some("Unknown error occurred")), Cmd.None)

      case Msg.Tick =>
        // Automatically refresh data every interval
        (model, RestApiClient.fetchDataForTab(model.activeTab))

      case Msg.ClearError =>
        (model.copy(error = None), Cmd.None)

      case Msg.ApplyFilter(filter) =>
        (model.copy(currentFilter = filter), Cmd.None)

  def view(model: Model): Html[Msg] =
    div(`class` := "app-container")(
      renderHeader,
      div(`class` := "main-content")(
        renderSidebar(model),
        renderContent(model)
      ),
      renderFooter
    )

  def renderHeader: Html[Msg] =
    header(`class` := "header")(
      h1(`class` := "header-title")("Security Monitoring Dashboard"),
      div(`class` := "header-controls")(
        button(`class` := "refresh-btn", onClick(Msg.FetchData))("Refresh Data"),
        span(`class` := "last-updated")("Last updated: " + java.time.LocalDateTime.now().toString)
      )
    )

  def renderSidebar(model: Model): Html[Msg] =
    nav(`class` := "sidebar")(
      div(`class` := "nav-section")(
        h3("Monitoring"),
        ul(`class` := "nav-links")(
          li(`class` := if model.activeTab == Tab.Dashboard then "active" else "")(
    a(href := "#", onClick(Msg.UpdateTab(Tab.Dashboard)))("Dashboard")
    ),
  li(`class` := if model.activeTab == Tab.Viruses then "active" else "")(
    a(href := "#", onClick(Msg.UpdateTab(Tab.Viruses)))("Viruses")
    ),
  li(`class` := if model.activeTab == Tab.Threats then "active" else "")(
    a(href := "#", onClick(Msg.UpdateTab(Tab.Threats)))("Threats")
    ),
  li(`class` := if model.activeTab == Tab.Vulnerabilities then "active" else "")(
    a(href := "#", onClick(Msg.UpdateTab(Tab.Vulnerabilities)))("Vulnerabilities")
    ),
  li(`class` := if model.activeTab == Tab.Traffic then "active" else "")(
    a(href := "#", onClick(Msg.UpdateTab(Tab.Traffic)))("Traffic Analysis")
    )
  )
  ),
  div(`class` := "system-status")(
    h3("System Status"),
    div(`class` := "status-indicator online")("Online"),
    div(`class` := "status-details")(
      p("Nodes: 24/24"),
      p("CPU: 32%"),
      p("Memory: 47%")
    )
  )
  )

  def renderContent(model: Model): Html[Msg] =
    div(`class` := "content-area")(
      model.error.map(err =>
        div(`class` := "error-message")(err)
      ).getOrElse(emptyHtml),

      model.activeTab match
        case Tab.Dashboard => renderDashboard(model)
        case Tab.Viruses => renderVirusesTab(model)
        case Tab.Threats => renderThreatsTab(model)
        case Tab.Vulnerabilities => renderVulnerabilitiesTab(model)
        case Tab.Traffic => renderTrafficTab(model)
    )

  def renderDashboard(model: Model): Html[Msg] =
    div(`class` := "dashboard-grid")(
      div(`class` := "dashboard-card")(
        h3("Virus Detections"),
        renderVirusChart(model),
        p(`class` := "card-summary")(s"Total detections: ${model.virusData.size}")
      ),
      div(`class` := "dashboard-card")(
        h3("Active Threats"),
        renderThreatSummary(model),
        p(`class` := "card-summary")(s"High severity: ${model.threatData.count(_.severity == "High")}")
      ),
      div(`class` := "dashboard-card")(
        h3("Vulnerabilities"),
        renderVulnSummary(model),
        p(`class` := "card-summary")(s"Critical: ${model.vulnData.count(_.severity == "Critical")}")
      ),
      div(`class` := "dashboard-card")(
        h3("Traffic Anomalies"),
        renderTrafficSummary(model),
        p(`class` := "card-summary")(s"Anomalies detected: ${model.trafficData.count(_.isAnomaly)}")
      ),
      div(`class` := "dashboard-card wide")(
        h3("Security Events Timeline"),
        renderTimeline(model)
      ),
      div(`class` := "dashboard-card wide")(
        h3("Network Status"),
        renderNetworkStatus(model)
      )
    )

  def renderVirusesTab(model: Model): Html[Msg] =
    div(`class` := "tab-content")(
      h2("Virus Monitoring"),
      div(`class` := "controls")(
        select(`class` := "filter-dropdown")(
          option(value := "all")("All Severity"),
          option(value := "high")("High"),
          option(value := "medium")("Medium"),
          option(value := "low")("Low")
        ),
        input(`type` := "text", placeholder := "Search detections...")
      ),
      div(`class` := "data-visualization")(
        renderVirusChart(model)
      ),
      table(`class` := "data-table")(
        thead(
          tr(
            th("Timestamp"),
            th("File"),
            th("Virus Type"),
            th("Location"),
            th("Status"),
            th("Actions")
          )
        ),
        tbody(
          model.virusData.map(virus =>
            tr(`class` := s"severity-${virus.severity.toLowerCase}")(
              td(virus.timestamp),
              td(virus.fileName),
              td(virus.virusType),
              td(virus.location),
              td(`class` := virus.status.toLowerCase)(virus.status),
              td(
                button(`class` := "action-btn")("Details"),
                button(`class` := "action-btn")("Quarantine")
              )
            )
          )
        )
      )
    )

  def renderThreatsTab(model: Model): Html[Msg] =
    div(`class` := "tab-content")(
      h2("Threat Monitoring"),
      div(`class` := "controls")(
        select(`class` := "filter-dropdown")(
          option(value := "all")("All Threat Types"),
          option(value := "intrusion")("Intrusion"),
          option(value := "dos")("DoS"),
          option(value := "malware")("Malware")
        ),
        input(`type` := "text", placeholder := "Search threats...")
      ),
      div(`class` := "threat-map")(
        div(`class` := "map-placeholder")(
          "Interactive Threat Map"
        )
      ),
      table(`class` := "data-table")(
        thead(
          tr(
            th("Timestamp"),
            th("Source"),
            th("Target"),
            th("Type"),
            th("Severity"),
            th("Status"),
            th("Actions")
          )
        ),
        tbody(
          model.threatData.map(threat =>
            tr(`class` := s"severity-${threat.severity.toLowerCase}")(
              td(threat.timestamp),
              td(threat.source),
              td(threat.target),
              td(threat.threatType),
              td(`class` := s"severity-label ${threat.severity.toLowerCase}")(threat.severity),
              td(`class` := threat.status.toLowerCase)(threat.status),
              td(
                button(`class` := "action-btn")("Investigate"),
                button(`class` := "action-btn")("Block")
              )
            )
          )
        )
      )
    )

  def renderVulnerabilitiesTab(model: Model): Html[Msg] =
    div(`class` := "tab-content")(
      h2("Vulnerability Assessment"),
      div(`class` := "controls")(
        select(`class` := "filter-dropdown")(
          option(value := "all")("All Systems"),
          option(value := "servers")("Servers"),
          option(value := "endpoints")("Endpoints"),
          option(value := "network")("Network Devices")
        ),
        input(`type` := "text", placeholder := "Search vulnerabilities...")
      ),
      div(`class` := "data-visualization")(
        div(`class` := "chart-placeholder")(
          "Vulnerability Severity Distribution"
        )
      ),
      table(`class` := "data-table")(
        thead(
          tr(
            th("ID"),
            th("System"),
            th("Description"),
            th("Severity"),
            th("Discovery Date"),
            th("Status"),
            th("Actions")
          )
        ),
        tbody(
          model.vulnData.map(vuln =>
            tr(`class` := s"severity-${vuln.severity.toLowerCase}")(
              td(vuln.id),
              td(vuln.system),
              td(vuln.description),
              td(`class` := s"severity-label ${vuln.severity.toLowerCase}")(vuln.severity),
              td(vuln.discoveryDate),
              td(`class` := vuln.status.toLowerCase)(vuln.status),
              td(
                button(`class` := "action-btn")("Patch"),
                button(`class` := "action-btn")("Details")
              )
            )
          )
        )
      )
    )

  def renderTrafficTab(model: Model): Html[Msg] =
    div(`class` := "tab-content")(
      h2("Network Traffic Analysis"),
      div(`class` := "controls")(
        select(`class` := "filter-dropdown")(
          option(value := "all")("All Traffic"),
          option(value := "anomalies")("Anomalies Only"),
          option(value := "normal")("Normal Traffic")
        ),
        input(`type` := "text", placeholder := "Search traffic data...")
      ),
      div(`class` := "data-visualization")(
        div(`class` := "chart-placeholder")(
          "Traffic Anomaly Graph"
        )
      ),
      table(`class` := "data-table")(
        thead(
          tr(
            th("Timestamp"),
            th("Source IP"),
            th("Destination IP"),
            th("Protocol"),
            th("Volume"),
            th("Status"),
            th("Actions")
          )
        ),
        tbody(
          model.trafficData.map(traffic =>
            tr(`class` := if traffic.isAnomaly then "anomaly" else "")(
            td(traffic.timestamp),
            td(traffic.sourceIp),
            td(traffic.destIp),
            td(traffic.protocol),
            td(traffic.volume + " MB"),
            td(`class` := if traffic.isAnomaly then "anomaly-status" else "normal-status")(
    if traffic.isAnomaly then "Anomaly" else "Normal"
    ),
  td(
    button(`class` := "action-btn")("Analyze"),
    button(`class` := "action-btn")("Block")
  )
  )
  )
  )
  )
  )

  def renderVirusChart(model: Model): Html[Msg] =
    div(`class` := "chart-container")(
      div(`class` := "chart", id := "virus-chart")(
        // In a real application, we would initialize chart visualization here
        // using the data from DataVisualizer.generateVirusTrendData(model.virusData)
        div(`class` := "chart-placeholder")(
          "Virus Detection Trend Chart"
        )
      ),
      div(`class` := "chart-legend")(
        div(`class` := "legend-item")(
          div(`class` := "legend-color high")(),
          span("High Severity")
        ),
        div(`class` := "legend-item")(
          div(`class` := "legend-color medium")(),
          span("Medium Severity")
        ),
        div(`class` := "legend-item")(
          div(`class` := "legend-color low")(),
          span("Low Severity")
        )
      )
    )

  def renderThreatSummary(model: Model): Html[Msg] =
    div(`class` := "summary-stats")(
      div(`class` := "stat")(
        span(`class` := "stat-value")(model.threatData.count(_.severity == "High").toString),
        span(`class` := "stat-label")("High")
      ),
      div(`class` := "stat")(
        span(`class` := "stat-value")(model.threatData.count(_.severity == "Medium").toString),
        span(`class` := "stat-label")("Medium")
      ),
      div(`class` := "stat")(
        span(`class` := "stat-value")(model.threatData.count(_.severity == "Low").toString),
        span(`class` := "stat-label")("Low")
      )
    )

  def renderVulnSummary(model: Model): Html[Msg] =
    div(`class` := "summary-stats")(
      div(`class` := "stat")(
        span(`class` := "stat-value")(model.vulnData.count(_.severity == "Critical").toString),
        span(`class` := "stat-label")("Critical")
      ),
      div(`class` := "stat")(
        span(`class` := "stat-value")(model.vulnData.count(_.severity == "High").toString),
        span(`class` := "stat-label")("High")
      ),
      div(`class` := "stat")(
        span(`class` := "stat-value")(model.vulnData.count(_.severity == "Medium").toString),
        span(`class` := "stat-label")("Medium")
      )
    )

  def renderTrafficSummary(model: Model): Html[Msg] =
    div(`class` := "summary-stats")(
      div(`class` := "stat")(
        span(`class` := "stat-value")(model.trafficData.count(_.isAnomaly).toString),
        span(`class` := "stat-label")("Anomalies")
      ),
      div(`class` := "stat")(
        span(`class` := "stat-value")(model.trafficData.filterNot(_.isAnomaly).size.toString),
        span(`class` := "stat-label")("Normal")
      )
    )

  def renderTimeline(model: Model): Html[Msg] =
    div(`class` := "timeline")(
      div(`class` := "timeline-placeholder")(
        "Security Events Timeline"
      )
    )

  def renderNetworkStatus(model: Model): Html[Msg] =
    div(`class` := "network-status")(
      div(`class` := "network-topology-placeholder")(
        "Network Topology Map"
      )
    )

  def renderFooter: Html[Msg] =
    footer(`class` := "footer")(
      p("Security Monitoring Dashboard © 2025"),
      p("Version 1.0.0")
    )

  def fetchData: Cmd[Msg] =
    RestApiClient.fetchDataForTab(Model.initial.activeTab)

  def subscriptions(model: Model): Sub[Msg] =
    Sub.every(30.seconds).map(_ => Msg.Tick)

end Main
