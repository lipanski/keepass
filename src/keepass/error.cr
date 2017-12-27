module Keepass
  module Error
    class Generic < Exception; end

    class Parsing < Generic; end

    class NotKdb < Parsing; end

    class FormatNotSupported < Parsing; end

    class MissingHeader < Parsing; end

    class CorruptedData < Parsing; end

    class CipherNotSupported < Parsing; end

    class CompressionNotSupported < Parsing; end

    class InnerEncryptionNotSupported < Parsing; end

    class DecryptionFailed < Generic; end
  end
end
