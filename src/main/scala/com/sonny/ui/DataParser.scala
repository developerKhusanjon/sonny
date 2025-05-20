package com.sonny.ui

import io.circe.*
import io.circe.parser.*

object DataParser:
  given Decoder[VirusData] = Decoder.instance { c =>
    for {
      id <- c.downField("id").as[String]
      timestamp <- c.downField("timestamp").as[String]
      fileName <- c.downField("fileName").as[String]
      virusType <- c.downField("virusType").as[String]
      severity <- c.downField("severity").as[String]
      location <- c.downField("location").as[String]
      status <- c.downField("status").as[String]
    } yield VirusData(id, timestamp, fileName, virusType, severity, location, status)
  }

  // Similar decoders for other data types...

  def parseVirusData(json: String): List[VirusData] =
    decode[List[VirusData]](json).getOrElse(Nil)

  def parseThreatData(json: String): List[ThreatData] =
    // Implementation similar to parseVirusData
    Model.generateDummyThreatData()

// Other parse methods with proper error handling...