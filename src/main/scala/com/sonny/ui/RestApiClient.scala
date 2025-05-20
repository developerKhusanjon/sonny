package com.sonny.ui

// RestApiClient.scala

import tyrian.Cmd

object RestApiClient:
//  private val baseUrl = "https://api.example.com"
//  private val headers = List(
//    Header("Accept", "application/json"),
//    Header("Authorization", "Bearer token")
//  )

  def fetchDataForTab(tab: Tab): Cmd.Emit[Msg] =
//    val endpoint = tab match {
//      case Tab.Dashboard => "/dashboard"
//      case Tab.Viruses => "/viruses"
//      // other cases...
//    }
    
    Cmd.Emit(Msg.Tick)

//    Http.send(
//      Request.get(baseUrl + endpoint)
//        .addHeaders(headers)
//        .withTimeout(30.seconds),
//      resultToMessage = 
//    )

  def requestAnalysis(itemId: String, itemType: String): Cmd.Emit[Msg] = ???

  def executeAction(itemId: String, actionType: String, itemType: String): Cmd.Emit[Msg] =
    Http.send(
      Request.post(baseUrl + s"/actions/$itemType/$itemId", Body.plainText(actionType))
        .addHeaders(headers),
      decoder
    )