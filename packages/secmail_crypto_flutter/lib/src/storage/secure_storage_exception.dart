/// Thrown when [FlutterSecureStorageProvider] cannot complete an operation.
class SecureStorageException implements Exception {
  SecureStorageException(this.message, {this.cause});

  final String message;
  final Object? cause;

  @override
  String toString() =>
      'SecureStorageException: $message${cause == null ? '' : ' ($cause)'}';
}
