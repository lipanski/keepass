module Keepass
  module Error
    class Generic < Exception; end

    class NotKdb < Generic; end

    class FormatNotSupported < Generic; end

    class CorruptedData < Generic; end

    class CipherNotSupported < Generic; end

    class CompressionNotSupported < Generic; end

    class InnerEncryptionNotSupported < Generic; end
  end
end
