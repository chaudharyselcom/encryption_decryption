import 'dart:developer' as developer;

import 'package:flutter/foundation.dart';
debugLogFlutter(String data) {
  if (kDebugMode) {
    developer.log("=PrintData====${data}==");
  }
}