require "gzip"
require "openssl"
require "openssl/cipher"
require "xml"

module Keepass
  class Parser
    KDBX_STABLE_MARKER = Bytes[0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5]
    AES_CIPHER_MARKER  = Bytes[0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a, 0xff]

    class GenericError < Exception; end

    class NotKdbxError < GenericError; end

    class CorruptedData < GenericError; end

    enum Cipher
      AES
      Unknown
    end

    enum Compression
      None
      Gzip
      Unknown
    end

    enum InnerStreamEncryption
      None
      Arc4Variant
      Salsa20
      Unknown
    end

    struct Block
      property id : UInt32
      property hash : Slice(UInt8)
      property data : Slice(UInt8)

      def initialize(@id, @hash, @data)
      end
    end

    struct Database
      property groups : Array(Group)

      def initialize
        @groups = Array(Group).new
      end
    end

    struct Group
      property uuid : String
      property name : String
      property entries : Array(Entry)

      def initialize(@uuid : String, @name : String, @entries : Array(Entry))
      end
    end

    struct Entry
      property uuid : String
      property title : String?
      property url : String?
      property user : String?
      property password : String?
      property notes : String?
      property created_at : Time?
      property updated_at : Time?
      property last_accessed_at : Time?
      property usage_count : Int32?

      def initialize(@uuid, @title, @url, @user, @password, @notes, @created_at, @updated_at, @last_accessed_at, @usage_count)
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
    @protected_stream_key : Bytes?
    @stream_start_bytes : Bytes?
    @inner_stream_encryption : InnerStreamEncryption?

    def initialize(@path : String, @password : String)
    end

    def parse!
      File.open(@path) do |io|
        # Marker
        kdbx_marker = Bytes.new(8)
        io.read(kdbx_marker)
        raise NotKdbxError.new unless kdbx_marker == KDBX_STABLE_MARKER

        # Version minor
        @version_minor = io.read_bytes(UInt16, IO::ByteFormat::LittleEndian)

        # Version major
        @version_major = io.read_bytes(UInt16, IO::ByteFormat::LittleEndian)

        # Headers
        loop do
          id = io.read_bytes(UInt8, IO::ByteFormat::LittleEndian)
          length = io.read_bytes(UInt16, IO::ByteFormat::LittleEndian)

          data = Bytes.new(length)
          io.read_fully(data)

          set_header(id, data)

          break if id == 0
        end

        # puts "cipher: #{@cipher}"
        # puts "compression: #{@compression}"
        # puts "master seed: #{@master_seed}"
        # puts "transform seed: #{@transform_seed}"
        # puts "transform rounds: #{@transform_rounds}"
        # puts "encryption iv: #{@encryption_iv}"
        # puts "protected stream key: #{@protected_stream_key}"
        # puts "stream start bytes: #{@stream_start_bytes.not_nil!.hexstring}"
        # puts "inner stream encryption: #{@inner_stream_encryption}"

        # Payload
        buffer = Array(UInt8).new
        io.each_byte { |byte| buffer << byte }

        encrypted_data = array_to_slice(buffer)

        decrypted_data = decrypt(encrypted_data)
        raise CorruptedData.new unless validate!(decrypted_data)

        blocks = Array(Block).new

        io = IO::Memory.new(array_to_slice(decrypted_data))
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

        puts xml

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
                    password = entry_node.children.find { |node| node.name == "Value" }.try(&.content)
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

        puts database
      end
    end

    def composite_key
      hashed_password = OpenSSL::Digest.new("SHA256").update(@password).digest

      OpenSSL::Digest.new("SHA256").update(hashed_password).digest
    end

    def master_key
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

    def decrypt(payload) : Array(UInt8)
      cipher = OpenSSL::Cipher.new("aes-256-cbc")
      cipher.decrypt
      cipher.key = master_key
      cipher.iv = @encryption_iv.not_nil!

      cipher.update(payload).to_a + cipher.final.to_a
    end

    def validate!(data) : Bool
      data.shift(@stream_start_bytes.not_nil!.size) == @stream_start_bytes.not_nil!.to_a
    end

    def version
      "#{@version_major}.#{@version_minor}"
    end

    def gzipped?
      @compression == Compression::Gzip
    end

    private def array_to_slice(array : Array)
      slice = Bytes.new(array.size)

      array.each_with_index do |byte, index|
        slice[index] = byte
      end

      slice
    end

    private def set_header(id, data)
      case id
      when  2 then set_cipher(data)
      when  3 then set_compression(data)
      when  4 then set_master_seed(data)
      when  5 then set_transform_seed(data)
      when  6 then set_transform_rounds(data)
      when  7 then set_encryption_iv(data)
      when  8 then set_protected_stream_key(data)
      when  9 then set_stream_start_bytes(data)
      when 10 then set_inner_stream_encryption(data)
      end
    end

    private def set_cipher(data)
      @cipher =
        case data
        when AES_CIPHER_MARKER then Cipher::AES
        else                        Cipher::Unknown
        end
    end

    private def set_compression(data)
      @compression =
        case IO::ByteFormat::LittleEndian.decode(UInt32, data)
        when 0 then Compression::None
        when 1 then Compression::Gzip
        else        Compression::Unknown
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

    private def set_protected_stream_key(data)
      @protected_stream_key = data
    end

    private def set_stream_start_bytes(data)
      @stream_start_bytes = data
    end

    private def set_inner_stream_encryption(data)
      @inner_stream_encryption =
        case IO::ByteFormat::LittleEndian.decode(UInt32, data)
        when 0 then InnerStreamEncryption::None
        when 1 then InnerStreamEncryption::Arc4Variant
        when 2 then InnerStreamEncryption::Salsa20
        else        InnerStreamEncryption::Unknown
        end
    end
  end
end

parser = Keepass::Parser.new("sample.kdbx", "sample")
parser.parse!
