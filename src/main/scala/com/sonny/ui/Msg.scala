package com.sonny.ui

import tyrian.*
import tyrian.http.*

enum Msg:
  case NoOp
  case UpdateTab(tab: Tab)
  case FetchData
  case DataResponse(response: Response)
  case Tick
  case ExecuteAction(itemId: String, actionType: String, itemType: String)
  case RequestAnalysis(itemId: String, itemType: String)
  case ClearError
  case ApplyFilter(filter: FilterType)