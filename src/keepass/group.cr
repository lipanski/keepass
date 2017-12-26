require "./entry"

module Keepass
  struct Group
    property uuid : String
    property name : String
    property entries : Array(Entry)

    def initialize(@uuid : String, @name : String, @entries : Array(Entry))
    end
  end
end
