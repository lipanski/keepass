require "gzip"
require "openssl"
require "openssl/cipher"
require "xml"
require "./error"
require "./database"
require "./group"
require "./entry"
require "../sodium/salsa20"

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
    @master_seed : Bytes?
    @encryption_iv : Bytes?
    @transform_seed : Bytes?
    @transform_rounds : UInt64?
    @stream_start_bytes : Bytes?
    @compression : Compression?
    @inner_encryption : InnerEncryption?
    @inner_encryption_key : Bytes?

    def initialize(@io : IO, @password : String)
    end

    def parse! : Database
      verify_marker!(@io)
      verify_format!(@io)
      set_version(@io)
      set_headers(@io)
      verify_required_headers!
      payload = read_payload(@io)
      @io.close

      decrypted_payload = decrypt(payload)
      verify_decrypted_payload!(decrypted_payload)
      data = build_data_from_blocks(decrypted_payload)
      xml_data = unzip_data_if_needed(data)

      parse_xml(xml_data)
    end

    private def verify_marker!(io : IO)
      kdb_marker = Bytes.new(4)
      io.read(kdb_marker)
      unless kdb_marker == KDB_MARKER
        raise Error::NotKdb.new
      end
    end

    private def verify_format!(io : IO)
      format_marker = Bytes.new(4)
      io.read_fully(format_marker)
      unless SUPPORTED_FORMATS.includes?(format_marker)
        raise Error::FormatNotSupported.new
      end
    end

    private def set_version(io : IO)
      @version_minor = io.read_bytes(UInt16, IO::ByteFormat::LittleEndian)
      @version_major = io.read_bytes(UInt16, IO::ByteFormat::LittleEndian)
    end

    private def version
      "#{@version_major}.#{@version_minor}"
    end

    private def set_headers(io : IO)
      loop do
        header_id = io.read_bytes(UInt8, IO::ByteFormat::LittleEndian)
        header_length = io.read_bytes(UInt16, IO::ByteFormat::LittleEndian)
        header_value = Bytes.new(header_length)
        io.read_fully(header_value)

        set_header(header_id, header_value)

        break if header_id == 0
      end
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

    private def verify_required_headers!
      raise Error::MissingHeader.new("master_seed") if @master_seed.nil?
      raise Error::MissingHeader.new("encryption_iv") if @encryption_iv.nil?
      raise Error::MissingHeader.new("transform_seed") if @transform_seed.nil?
      raise Error::MissingHeader.new("transform_rounds") if @transform_rounds.nil?
      raise Error::MissingHeader.new("stream_start_bytes") if @stream_start_bytes.nil?
      raise Error::MissingHeader.new("inner_encryption_key") if @inner_encryption_key.nil? && salsa20?
    end

    private def read_payload(io : IO) : Array(UInt8)
      Array(UInt8).new.tap do |buffer|
        io.each_byte { |byte| buffer << byte }
      end
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
        transformed_key_array = cipher.update(transformed_key).to_a + cipher.final.to_a
        transformed_key = Slice.new(transformed_key_array.to_unsafe, transformed_key_array.size)
      end

      hashed_transformed_key = OpenSSL::Digest.new("SHA256").update(transformed_key).digest
      full_key_array = @master_seed.not_nil!.to_a + hashed_transformed_key.to_a
      full_key = Slice.new(full_key_array.to_unsafe, full_key_array.size)

      OpenSSL::Digest.new("SHA256").update(full_key).digest
    end

    private def decrypt(payload : Array(UInt8)) : Array(UInt8)
      decrypt(Slice.new(payload.to_unsafe, payload.size))
    end

    private def decrypt(payload : Slice(UInt8)) : Array(UInt8)
      cipher = OpenSSL::Cipher.new("aes-256-cbc")
      cipher.decrypt
      cipher.key = master_key
      cipher.iv = @encryption_iv.not_nil!

      cipher.update(payload).to_a + cipher.final.to_a
    end

    private def verify_decrypted_payload!(data)
      unless data.shift(@stream_start_bytes.not_nil!.size) == @stream_start_bytes.not_nil!.to_a
        raise Error::CorruptedData.new
      end
    end

    private def build_data_from_blocks(decrypted_data : Array(UInt8)) : Array(UInt8)
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

      blocks.sort_by!(&.id).reduce(Array(UInt8).new) { |acc, el| acc += el.data.to_a }
    end

    private def gzipped?
      @compression == Compression::Gzip
    end

    private def unzip_data_if_needed(data : Array(UInt8)) : String
      slice = Slice.new(data.to_unsafe, data.size)

      if gzipped?
        stream = IO::Memory.new(slice, writeable: false)
        gzip = Gzip::Reader.new(stream)
        gzip.gets_to_end
      else
        String.new(slice)
      end
    end

    private def salsa20? : Bool
      @inner_encryption == InnerEncryption::Salsa20
    end

    private def salsa20 : Sodium::Salsa20
      @salsa20 ||=
        Sodium::Salsa20.new(
          OpenSSL::Digest.new("SHA256").update(@inner_encryption_key.not_nil!).digest,
          INNER_STREAM_IV
        )
    end

    private def decrypt_inner_value(value) : String
      if salsa20?
        salsa20.decrypt(value)
      else
        value
      end
    end

    private def parse_xml(xml_data : String) : Database
      database = Database.new(version)

      document = XML.parse(xml_data)
      top_node = document.first_element_child.not_nil!
      root_node = top_node.children.find { |node| node.name == "Root" }.not_nil!
      group_nodes = root_node.children.select { |node| node.name == "Group" }

      group_nodes.each do |group_node|
        database.groups << parse_group_node(group_node)
      end

      database
    end

    private def parse_group_node(group_node : XML::Node) : Group
      uuid, name, entries = nil, nil, Array(Entry).new
      group_node.children.each do |group_attribute_node|
        case group_attribute_node.name
        when "UUID"
          uuid = group_attribute_node.content
        when "Name"
          name = group_attribute_node.content
        when "Entry"
          entries << parse_entry_node(group_attribute_node)
        end
      end

      Group.new(uuid.not_nil!, name.not_nil!, entries)
    end

    private def parse_entry_node(entry_root_node : XML::Node) : Entry
      uuid, data, created_at, updated_at, last_accessed_at, usage_count = nil, Hash(String, String).new, nil, nil, nil, nil
      entry_root_node.children.each do |entry_node|
        case entry_node.name
        when "UUID"
          uuid = entry_node.content
        when "Times"
          created_at = parse_time_node(entry_node, "CreationTime")
          updated_at = parse_time_node(entry_node, "LastModificationTime")
          last_accessed_at = parse_time_node(entry_node, "LastAccessTime")
          usage_count = parse_int_node(entry_node, "UsageCount")
        when "String"
          key_node = find_child_node(entry_node, "Key")
          value_node = find_child_node(entry_node, "value")
          if key_node && value_node
            name = key_node.content.underscore
            value =
              if value_node["Protected"]? == "True"
                decrypt_inner_value(value_node.content)
              else
                value_node.content
              end

            data[name] = value
          end
        end
      end

      Entry.new(uuid.not_nil!, data, created_at, updated_at, last_accessed_at, usage_count)
    end

    private def find_child_node(parent_node : XML::Node, node_name : String) : XML::Node?
      parent_node.children.find { |node| node.name == node_name }
    end

    private def parse_time_node(parent_node : XML::Node, node_name : String) : Time?
      find_child_node(parent_node, node_name)
        .try(&.content)
        .try { |content| Time.parse(content, Time::Format::ISO_8601_DATE_TIME.pattern) }
    end

    private def parse_int_node(parent_node : XML::Node, node_name : String) : Int32?
      find_child_node(parent_node, node_name)
        .try(&.content)
        .try { |content| content.to_i }
    end
  end
end
