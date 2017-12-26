require "./group"

module Keepass
  struct Database
    property groups : Array(Group)

    def initialize
      @groups = Array(Group).new
    end
  end
end
