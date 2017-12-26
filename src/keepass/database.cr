require "./group"

module Keepass
  struct Database
    property version : String
    property groups : Array(Group)

    def initialize(@version)
      @groups = Array(Group).new
    end
  end
end
