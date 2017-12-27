require "./keepass/parser"
require "./keepass/database"

module Keepass
  def self.parse!(path : String, password : String, key_file_path : String? = nil) : Database
    parse!(File.open(path), password, key_file_path ? File.open(key_file_path) : nil)
  end

  def self.parse!(io : IO, password : String, key_file : IO? = nil) : Database
    Parser.new(io, password, key_file).parse!
  end
end
