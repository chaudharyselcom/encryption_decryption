library encryption_decryption;

import 'package:encrypt/encrypt.dart' as enc;
import 'package:pointycastle/asymmetric/api.dart';
import 'dart:math' as math;

import 'common.dart';

/// A Calculator.
class Encypted {
  static String publicKey = "";
}

String _chars =
    'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz1234567890';
final math.Random _rnd = math.Random();

String getRandomString(int length) => String.fromCharCodes(
      Iterable.generate(
        length,
        (_) => _chars.codeUnitAt(
          _rnd.nextInt(_chars.length),
        ),
      ),
    );

Future<String> encryptData({
  required String data,
  required String keyInString,
  required String ivInString,
}) async {
  Stopwatch stopwatch = Stopwatch()..start();

  String aesEncryptedText = await aesEncrypt(
    data: data,
    keyInString: keyInString,
    ivInString: ivInString,
  );
  print('whole encryption time ${stopwatch.elapsed.inMilliseconds}');
  stopwatch.stop();
  return aesEncryptedText;
}

Future<String> aesEncrypt({
  required String data,
  required String keyInString,
  required String ivInString,
}) async {
  final key = enc.Key.fromUtf8(keyInString);
  final iv = enc.IV.fromUtf8(ivInString);

  final encrypter = enc.Encrypter(enc.AES(key, mode: enc.AESMode.cbc));
  final encrypted = encrypter.encrypt(data, iv: iv);

  debugLogFlutter(
      "Iv:$ivInString\nKey:$keyInString\nEncrypted: ${encrypted.base64} ");

  String divider = "FrIvOlGgLIrST";
  String keyIvRsaEncrypted = await rsaEncryption(
    aesEncryptedText: "$keyInString$ivInString",
  );
  return "$keyIvRsaEncrypted$divider${encrypted.base64}";
}

Future<String> rsaEncryption({required String aesEncryptedText}) async {
  enc.RSAKeyParser keyParser = enc.RSAKeyParser();

  RSAAsymmetricKey publicKeyParser =
      keyParser.parse(Encypted.publicKey); //public
  final publicKey = RSAPublicKey(
    publicKeyParser.modulus!,
    publicKeyParser.exponent!,
  );
  final encrypter = enc.Encrypter(
    enc.RSA(
      publicKey: publicKey,
    ),
  );

  final encrypted = encrypter.encrypt(aesEncryptedText);
  debugLogFlutter("RSA Encrypted text: ${encrypted.base64}");
  return encrypted.base64;
}

String onlyAESEncryption({
  required String data,
  required String keyInString,
  required String ivInString,
}) {
  final key = enc.Key.fromUtf8(keyInString);
  final iv = enc.IV.fromUtf8(ivInString);

  final encrypter = enc.Encrypter(enc.AES(key, mode: enc.AESMode.cbc));
  final encrypted = encrypter.encrypt(data, iv: iv);

  debugLogFlutter(
      "Iv:$ivInString\nKey:$keyInString\nEncrypted: ${encrypted.base64} ");

// String divider = "FrIvOlGgLIrST";

  return encrypted.base64;
}

Future<String> aesDecrypt({
  required String data,
  required String keyInString,
  required String ivInString,
}) async {
  try {
    Stopwatch stopwatch = Stopwatch()..start();
    data = data.replaceAll('\\', '');
    final key = enc.Key.fromUtf8(keyInString);
    final iv = enc.IV.fromUtf8(ivInString);
//  data = data.toString().split("=")[0];
    data = data.replaceAll("\n", "");
    data = data.replaceAll("\"", "");

    // data = data.replaceAll("\\/", "/");
    // debugPrint("====data==492======${data}===");
    final encrypter = enc.Encrypter(enc.AES(
      key,
      mode: enc.AESMode.cbc,
    ));

    String decrypted = encrypter.decrypt64(data, iv: iv);
    print('whole decrypt time ${stopwatch.elapsed.inMilliseconds}');
    debugLogFlutter("Iv:$ivInString\nKey:$keyInString\nDecrypted: $decrypted ");
    stopwatch.stop();
    return decrypted;
  } catch (error) {
    debugLogFlutter("==aesDecrypt error==507==${error}===");
    return "";
  }
}

String public = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuLJpD8BHpGJNXhd0dUsh
tABKbpCPxV45W7BQ6aCOH+FzmZapKOipeZGtdMgpbgikr5PuvSGuSp96xKKHUnBu
gWGhiXh1p20RPNYeX9owtMmytVattJBSoAF2IJ5BDe+m6F3FS9jkPsl3nGaHJXZb
l2pd29/uh1atSgGwLLRkO6SRYzfUFG5W/p6f59N2cyWsjO2M4XalJQ6VbggZjs/a
R8hnWrciiUFkeroOFbRt8kFU3uPmKzTmOs+sRu5hZg7K+S/3nrC+gvTKt0nwSySY
ZNFPyq51jMpcmvTM+H6hjHrHq6EEhm8uuIIACJTuG0Gqw+HzPNJJvAhFySXgdl5u
7wIDAQAB
-----END PUBLIC KEY-----''';

class KeyIvModel {
  String keyInString = "";
  String ivInString = "";

  KeyIvModel({required this.keyInString, required this.ivInString});
}
