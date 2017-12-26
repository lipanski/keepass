require "./keepass/parser"
require "./keepass/database"

module Keepass
  def self.parse!(path : String, password : String) : Database
    parse!(File.open(path), password)
  end

  def self.parse!(io : IO, password : String) : Database
    Parser.new(io, password).parse!
  end
end
