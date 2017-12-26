require "base64"
require "./libsodium"

module Sodium
  class Salsa20
    def initialize(key : String, nonce : String)
      @key = key.to_slice
      @nonce = nonce.to_slice
    end

    def initialize(@key : Slice(UInt8), @nonce : Slice(UInt8))
    end

    def encrypt(data : String) : String
      data_slice = data.to_slice
      encrypted = Bytes.new(data_slice.size)

      LibSodium.crypto_stream_salsa20_xor(
        encrypted,
        data_slice,
        data_slice.size,
        @nonce,
        @key
      )

      Base64.encode(encrypted)
    end

    def decrypt(data : String) : String
      data_slice = Base64.decode(data)
      decrypted = Bytes.new(data_slice.size)

      LibSodium.crypto_stream_salsa20_xor(
        decrypted,
        data_slice,
        data_slice.size,
        @nonce,
        @key
      )

      String.new(decrypted)
    end
  end
end
