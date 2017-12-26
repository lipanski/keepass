@[Link("libsodium")]
lib LibSodium
  fun crypto_stream_salsa20_xor(buffer : LibC::Char*, message : LibC::Char*, message_length : LibC::UInt, nonce : LibC::Char*, key : LibC::Char*) : LibC::Int
end
