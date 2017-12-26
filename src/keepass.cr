require "gzip"
require "openssl"
require "openssl/cipher"
require "xml"
require "./keepass/*"
require "./sodium/salsa20"

module Keepass
  class Parser
    KDB_MARKER            = Bytes[0x03, 0xd9, 0xa2, 0x9a]
    KDBX_PRE_V2_MARKER    = Bytes[0xB5, 0x4B, 0xFB, 0x66]
    KDBX_V2_STABLE_MARKER = Bytes[0x67, 0xfb, 0x4b, 0xb5]
    SUPPORTED_FORMATS     = [KDBX_PRE_V2_MARKER, KDBX_V2_STABLE_MARKER]
    AES_CIPHER_MARKER     = Bytes[0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a, 0xff]
    INNER_STREAM_IV       = Bytes[0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A]

    enum Cipher
      AES
    end

    enum Compression
      None
      Gzip
    end

    enum InnerEncryption
      None
      Salsa20
    end

    struct Block
      property id : UInt32
      property hash : Slice(UInt8)
      property data : Slice(UInt8)

      def initialize(@id, @hash, @data)
      end
    end

    @version_major : UInt16?
    @version_minor : UInt16?
    @cipher : Cipher?
    @compression : Compression?
    @master_seed : Bytes?
    @transform_seed : Bytes?
    @transform_rounds : UInt64?
    @encryption_iv : Bytes?
    @inner_encryption_key : Bytes?
    @stream_start_bytes : Bytes?
    @inner_encryption : InnerEncryption?

    def initialize(@path : String, @password : String)
    end

    def parse!
      file_io = File.open(@path)

      # Marker
      kdb_marker = Bytes.new(4)
      file_io.read(kdb_marker)
      unless kdb_marker == KDB_MARKER
        raise Error::NotKdb.new
      end

      # Format marker
      format_marker = Bytes.new(4)
      file_io.read_fully(format_marker)
      unless SUPPORTED_FORMATS.includes?(format_marker)
        raise Error::FormatNotSupported.new
      end

      # Version minor
      @version_minor = file_io.read_bytes(UInt16, IO::ByteFormat::LittleEndian)

      # Version major
      @version_major = file_io.read_bytes(UInt16, IO::ByteFormat::LittleEndian)

      # Headers
      loop do
        header_id = file_io.read_bytes(UInt8, IO::ByteFormat::LittleEndian)
        header_length = file_io.read_bytes(UInt16, IO::ByteFormat::LittleEndian)
        header_value = Bytes.new(header_length)
        file_io.read_fully(header_value)

        set_header(header_id, header_value)

        break if header_id == 0
      end

      # Payload
      buffer = Array(UInt8).new
      file_io.each_byte { |byte| buffer << byte }

      # No need for the file handler any more
      file_io.close

      encrypted_data = Slice.new(buffer.to_unsafe, buffer.size)

      decrypted_data = decrypt(encrypted_data)
      unless validate!(decrypted_data)
        raise Error::CorruptedData.new
      end

      blocks = Array(Block).new

      io = IO::Memory.new(Slice.new(decrypted_data.to_unsafe, decrypted_data.size))
      until io.peek == Bytes.empty
        block_id = io.read_bytes(UInt32, IO::ByteFormat::LittleEndian)

        block_hash = Bytes.new(32)
        io.read_fully(block_hash)

        block_size = io.read_bytes(UInt32, IO::ByteFormat::LittleEndian)

        block_data = Bytes.new(block_size)
        io.read_fully(block_data)

        blocks.push(Block.new(block_id, block_hash, block_data))
      end

      data = blocks.sort_by!(&.id).reduce(Array(UInt8).new) { |acc, el| acc += el.data.to_a }
      slice = array_to_slice(data)

      if gzipped?
        stream = IO::Memory.new(slice, writeable: false)
        gzip = Gzip::Reader.new(stream)
        xml = gzip.gets_to_end
      else
        xml = String.new(slice)
      end

      salsa20 = Sodium::Salsa20.new(OpenSSL::Digest.new("SHA256").update(@inner_encryption_key.not_nil!).digest, INNER_STREAM_IV)

      database = Database.new
      document = XML.parse(xml)
      top_node = document.first_element_child.not_nil!
      root_node = top_node.children.find { |node| node.name == "Root" }.not_nil!
      group_nodes = root_node.children.select { |node| node.name == "Group" }
      group_nodes.each do |group_node|
        uuid, name, entries = nil, nil, Array(Entry).new
        group_node.children.each do |group_attribute_node|
          case group_attribute_node.name
          when "UUID"
            uuid = group_attribute_node.content
          when "Name"
            name = group_attribute_node.content
          when "Entry"
            uuid, title, url, user, password, notes, created_at, updated_at, last_accessed_at, usage_count = nil, nil, nil, nil, nil, nil, nil, nil, nil, nil
            group_attribute_node.children.each do |entry_node|
              case entry_node.name
              when "UUID"
                uuid = entry_node.content
              when "Times"
                created_at = entry_node.children.find { |node| node.name == "CreationTime" }.try(&.content).try { |str| Time.parse(str, Time::Format::ISO_8601_DATE_TIME.pattern) }
                updated_at = entry_node.children.find { |node| node.name == "LastModificationTime" }.try(&.content).try { |str| Time.parse(str, Time::Format::ISO_8601_DATE_TIME.pattern) }
                last_accessed_at = entry_node.children.find { |node| node.name == "LastAccessTime" }.try(&.content).try { |str| Time.parse(str, Time::Format::ISO_8601_DATE_TIME.pattern) }
                usage_count = entry_node.children.find { |node| node.name == "UsageCount" }.try(&.content).try { |str| str.to_i }
              when "String"
                case entry_node.children.find { |node| node.name == "Key" }.try(&.content)
                when "Title"
                  title = entry_node.children.find { |node| node.name == "Value" }.try(&.content)
                when "URL"
                  url = entry_node.children.find { |node| node.name == "Value" }.try(&.content)
                when "UserName"
                  user = entry_node.children.find { |node| node.name == "Value" }.try(&.content)
                when "Password"
                  if password_node = entry_node.children.find { |node| node.name == "Value" }
                    password =
                      if password_node["Protected"] == "True"
                        salsa20.decrypt(password_node.content)
                      else
                        password_node.content
                      end
                  end
                when "Notes"
                  notes = entry_node.children.find { |node| node.name == "Value" }.try(&.content)
                end
              end
            end

            entries << Entry.new(uuid.not_nil!, title, url, user, password, notes, created_at, updated_at, last_accessed_at, usage_count)
          end
        end

        database.groups << Group.new(uuid.not_nil!, name.not_nil!, entries)
      end

      database
    end

    private def composite_key
      hashed_password = OpenSSL::Digest.new("SHA256").update(@password).digest

      OpenSSL::Digest.new("SHA256").update(hashed_password).digest
    end

    private def master_key
      cipher = OpenSSL::Cipher.new("aes-256-ecb")
      cipher.encrypt
      cipher.key = @transform_seed.not_nil!
      cipher.padding = false

      transformed_key = composite_key
      @transform_rounds.not_nil!.times do
        transformed_key = array_to_slice(cipher.update(transformed_key).to_a + cipher.final.to_a)
      end

      hashed_transformed_key = OpenSSL::Digest.new("SHA256").update(transformed_key).digest
      full_key = array_to_slice(@master_seed.not_nil!.to_a + hashed_transformed_key.to_a)

      OpenSSL::Digest.new("SHA256").update(full_key).digest
    end

    private def decrypt(payload) : Array(UInt8)
      cipher = OpenSSL::Cipher.new("aes-256-cbc")
      cipher.decrypt
      cipher.key = master_key
      cipher.iv = @encryption_iv.not_nil!

      cipher.update(payload).to_a + cipher.final.to_a
    end

    private def validate!(data) : Bool
      data.shift(@stream_start_bytes.not_nil!.size) == @stream_start_bytes.not_nil!.to_a
    end

    private def version
      "#{@version_major}.#{@version_minor}"
    end

    private def gzipped?
      @compression == Compression::Gzip
    end

    private def array_to_slice(array : Array)
      Slice.new(array.to_unsafe, array.size)
    end

    private def set_header(id, data)
      case id
      when  2 then set_cipher(data)
      when  3 then set_compression(data)
      when  4 then set_master_seed(data)
      when  5 then set_transform_seed(data)
      when  6 then set_transform_rounds(data)
      when  7 then set_encryption_iv(data)
      when  8 then set_inner_encryption_key(data)
      when  9 then set_stream_start_bytes(data)
      when 10 then set_inner_encryption(data)
      end
    end

    private def set_cipher(data)
      @cipher =
        case data
        when AES_CIPHER_MARKER then Cipher::AES
        else                        raise Error::CipherNotSupported.new
        end
    end

    private def set_compression(data)
      @compression =
        case IO::ByteFormat::LittleEndian.decode(UInt32, data)
        when 0 then Compression::None
        when 1 then Compression::Gzip
        else        raise Error::CompressionNotSupported.new
        end
    end

    private def set_master_seed(data)
      @master_seed = data
    end

    private def set_transform_seed(data)
      @transform_seed = data
    end

    private def set_transform_rounds(data)
      @transform_rounds = IO::ByteFormat::LittleEndian.decode(UInt64, data)
    end

    private def set_encryption_iv(data)
      @encryption_iv = data
    end

    private def set_inner_encryption_key(data)
      @inner_encryption_key = data
    end

    private def set_stream_start_bytes(data)
      @stream_start_bytes = data
    end

    private def set_inner_encryption(data)
      @inner_encryption =
        case IO::ByteFormat::LittleEndian.decode(UInt32, data)
        when 0 then InnerEncryption::None
        when 2 then InnerEncryption::Salsa20
        else        raise Error::InnerEncryptionNotSupported.new
        end
    end
  end
end

parser = Keepass::Parser.new("sample.kdbx", "sample")
puts parser.parse!
